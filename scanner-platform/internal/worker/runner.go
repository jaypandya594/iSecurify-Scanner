package worker

import (
	"context"
	"fmt"
	"log"
	"time"

	"scanner-platform/internal/models"
	"scanner-platform/scanner-engine/core"
	"scanner-platform/scanner-engine/fix"
	"scanner-platform/scanner-engine/scanners/collection"
	"scanner-platform/scanner-engine/scanners/discovery"
	"scanner-platform/scanner-engine/scanners/filters"
)

func RunFix(ctx context.Context, job *models.FixScanJob) (any, error) {

	null := models.FixScanResult{}

	log.Println("================================")
	log.Println("Received fix job")
	log.Println("================================")

	log.Printf("Scan ID: %s", job.ScanID)
	log.Printf("Domain: %s", job.Domain)
	log.Printf("Fix Type: %s", job.FixType)

	log.Printf("Fix started: %s (%s)", job.ScanID, job.Domain)

	result := models.FixScanResult{}
	var err error

	if job.FixType == "port" {

		fmt.Println("================================")
		fmt.Println("Processing fix request")
		fmt.Println("================================")

		fmt.Println("Fix Port-Scanner Running...")

		fmt.Println("Running verification")

		result, err = fix.PortFix(ctx, job)
		if err != nil {
			log.Println("Fix failed:", err)
			return null, err
		}

		fmt.Println("Verification completed")
		fmt.Println("Fix Port-Scanner Completed.")
	}

	// ========================================
	// SEND WEBHOOK
	// ========================================

	fmt.Println("Sending webhook result")

	res, err := send_fix_result_webhook(result)
	if err != nil {
		log.Println("Webhook failed:", err)
		return nil, err
	}

	fmt.Println("Fix workflow completed successfully")

	return res, nil
}

func RunMain(ctx context.Context, job *models.ScanJob) (any, error) {

	log.Printf("Scan started: %s (%s)", job.ScanID, job.Target)

	fmt.Println("Pipeline started for domain:", job.Target)

	fmt.Println("Pipeline 1 : subdomain discovery")

	registry := core.NewRegistry()

	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewDiscoveryPipeline(registry)

	results, err := pipeline.ExecuteDiscoveryScanner(ctx, job.Target)
	if err != nil {
		return nil, err
	}

	discovery_payload := models.ScanNotification{
		ScanID: job.ScanID,
		Target: job.Target,
		Event:  "subdomain_discovery_completed",
		Status: "completed",
	}

	discovery_res, err := send_webhook_notification(discovery_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Subdomains Found:", len(results.Data.([]string)), discovery_res)

	fmt.Println("Pipeline 2 : filter subdomain")

	filter_registry := core.NewFilterScannerRegistry()

	filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
	filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
	filter_registry.RegisterFilterScanner(filters.NewHTTPFilter())

	filter_pipeline := core.NewFilterPipeline(filter_registry)

	filter_pipeline_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, job.Target)
	if err != nil {
		return nil, err
	}

	filter_payload := models.ScanNotification{
		ScanID: job.ScanID,
		Target: job.Target,
		Event:  "subdomain_filter_completed",
		Status: "completed",
	}

	filter_res, err := send_webhook_notification(filter_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Filtered Subdomains Found:", len(filter_pipeline_results.Data.([]interface{})), filter_res)

	fmt.Println("Scanner 3 : Data collection")

	collection_registry := core.NewCollectionRegistry()

	collection_registry.RegisterCollectionScanner(collection.NewDNSDataOutput())
	collection_registry.RegisterCollectionScanner(collection.NewHTTPXFilterOutput())
	collection_registry.RegisterCollectionScanner(collection.NewPortFilter())
	collection_registry.RegisterCollectionScanner(collection.NewTLSDataCollection())
	collection_registry.RegisterCollectionScanner(collection.NewMailSecurityDataCollection())

	collection_pipeline := core.NewCollectionPipeline(collection_registry)

	collection_data_results, err := collection_pipeline.ExecuteCollectionScanenrs(ctx, filter_pipeline_results, job.Target)
	if err != nil {
		return nil, err
	}

	collection_payload := models.ScanNotification{
		ScanID: job.ScanID,
		Target: job.Target,
		Event:  "subdomain_collection_completed",
		Status: "completed",
	}

	collection_res, err := send_webhook_notification(collection_payload)
	if err != nil {
		log.Printf("Failed to send webhook notification: %v", err)
	}

	fmt.Println("Total Results Found:", len(collection_data_results.Data.(map[string]interface{})), collection_res)

	scanResult := models.ScanResult{
		ScanID:    job.ScanID,
		Target:    job.Target,
		Status:    "completed",
		Data:      collection_data_results.Data,
		Timestamp: time.Now(),
	}

	fmt.Println("Final Results:",
		len(scanResult.Data.(map[string]interface{})["subdomains"].([]interface{})))

	res, err := send_scan_result_webhook(scanResult)
	if err != nil {
		return nil, err
	}

	return res, nil
}
