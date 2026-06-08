import React, { useState, useEffect } from "react";
import { generatePromoCode, getPromoCodes } from "../services/api";

function AdminSubscription() {
  const [promoCodes, setPromoCodes] = useState([]);
  const [promoLoading, setPromoLoading] = useState(false);
  const [generatingPromo, setGeneratingPromo] = useState(false);
  const [notification, setNotification] = useState({ text: "", type: "" });

  const showNotification = (text, type = "success") => {
    setNotification({ text, type });
    setTimeout(() => setNotification({ text: "", type: "" }), 3000);
  };

  useEffect(() => {
    fetchPromoCodes();
  }, []);

  const fetchPromoCodes = async () => {
    setPromoLoading(true);
    try {
      const data = await getPromoCodes(localStorage.getItem("token"));
      const sortedCodes = (data || []).sort((a, b) => {
        if (a.is_used === b.is_used) return 0;
        return a.is_used ? 1 : -1;
      });
      setPromoCodes(sortedCodes);
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setPromoLoading(false);
    }
  };

  const handleGeneratePromo = async () => {
    setGeneratingPromo(true);
    try {
      await generatePromoCode(localStorage.getItem("token"));
      showNotification("Promo code generated successfully");
      fetchPromoCodes();
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setGeneratingPromo(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface">
      {notification.text && (
        <div className={`fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg ${notification.type === 'error' ? 'bg-red-500 text-white' : 'bg-emerald-500 text-white'
          }`}>
          {notification.text}
        </div>
      )}

      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-0 py-4 sm:py-6 lg:py-8">
        {/* Header */}
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="mb-2 text-2xl font-black tracking-tight text-on-surface sm:text-3xl lg:text-4xl">
              Subscription Management
            </h2>
            <p className="max-w-2xl text-sm text-on-surface-variant sm:text-base">
              Define service tiers, adjust pricing models, manage enterprise
              features, and generate promotional codes.
            </p>
          </div>
        </div>

        {/* Pricing Cards */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-4">
          <div className="bg-surface-container-lowest p-6 rounded-3xl shadow-sm border border-primary/10 relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-4">
              <span className="px-2 py-1 bg-primary/10 text-primary text-[10px] font-bold rounded-lg uppercase">
                Popular
              </span>
            </div>
            <div className="w-12 h-12 rounded-2xl bg-primary-container/30 flex items-center justify-center text-primary mb-6">
              <span className="material-symbols-outlined">rocket_launch</span>
            </div>
            <h3 className="text-xl font-black text-on-surface mb-1">
              Enterprise Plus
            </h3>
            <p className="text-3xl font-black text-primary mb-4">
              $499
              <span className="text-sm font-medium text-on-surface-variant">
                /mo
              </span>
            </p>
            <div className="space-y-3 mb-8">
              <div className="flex items-center gap-2 text-xs font-medium text-on-surface-variant">
                <span className="material-symbols-outlined text-emerald-500 text-sm">
                  check_circle
                </span>{" "}
                Unlimited Scans
              </div>
            </div>
          </div>

          <div className="bg-surface-container-lowest p-6 rounded-3xl shadow-sm group">
            <div className="w-12 h-12 rounded-2xl bg-tertiary-container/30 flex items-center justify-center text-tertiary mb-6">
              <span className="material-symbols-outlined">business_center</span>
            </div>
            <h3 className="text-xl font-black text-on-surface mb-1">
              Business Pro
            </h3>
            <p className="text-3xl font-black text-on-surface mb-4">
              $199
              <span className="text-sm font-medium text-on-surface-variant">
                /mo
              </span>
            </p>
          </div>

          <div className="bg-surface-container-lowest p-6 rounded-3xl shadow-sm group">
            <div className="w-12 h-12 rounded-2xl bg-secondary-container/30 flex items-center justify-center text-secondary mb-6">
              <span className="material-symbols-outlined">work</span>
            </div>
            <h3 className="text-xl font-black text-on-surface mb-1">
              Standard
            </h3>
            <p className="text-3xl font-black text-on-surface mb-4">
              $49
              <span className="text-sm font-medium text-on-surface-variant">
                /mo
              </span>
            </p>
          </div>

          <div className="bg-surface-container-lowest p-6 rounded-3xl shadow-sm group">
            <div className="w-12 h-12 rounded-2xl bg-outline-variant/10 flex items-center justify-center text-outline-variant mb-6">
              <span className="material-symbols-outlined">hourglass_top</span>
            </div>
            <h3 className="text-xl font-black text-on-surface mb-1">
              Free Tier
            </h3>
            <p className="text-3xl font-black text-on-surface mb-4">
              $0
            </p>
          </div>
        </div>

        {/* Promo Codes & Editor Config */}
        <div className="grid grid-cols-1 gap-8 xl:grid-cols-12">
          <div className="col-span-1 xl:col-span-7 space-y-8">
            <div className="bg-surface-container-lowest rounded-3xl overflow-hidden shadow-sm">
              <div className="flex flex-col gap-4 border-b border-surface-container px-4 py-5 sm:px-6 sm:py-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
                <div>
                  <h3 className="text-xl font-bold">Generated Promo Codes</h3>
                  <p className="text-xs text-on-surface-variant mt-1">Single-use tokens to grant Enterprise access.</p>
                </div>
                <button
                  onClick={handleGeneratePromo}
                  disabled={generatingPromo}
                  className="px-6 py-2 bg-gradient-to-br from-primary to-primary-dim text-white rounded-xl font-semibold text-sm shadow-lg shadow-primary/20 hover:opacity-90 transition-all flex items-center gap-2 disabled:opacity-50"
                >
                  {generatingPromo ? (
                    <span className="material-symbols-outlined text-sm animate-spin">refresh</span>
                  ) : (
                    <span className="material-symbols-outlined text-sm">add</span>
                  )}
                  Generate New Code
                </button>
              </div>

              {promoLoading ? (
                <div className="p-12 text-center text-slate-500">Loading codes...</div>
              ) : promoCodes.length === 0 ? (
                <div className="p-12 text-center text-slate-500">No promo codes generated yet.</div>
              ) : (
                <div className="overflow-x-auto max-h-[300px]">
                  <table className="w-full text-left border-collapse">
                    <thead className="bg-surface-container-low border-b border-surface-container sticky top-0">
                      <tr>
                        <th className="px-8 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Code</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Status</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Used At</th>
                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Used By</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-surface-container">
                      {promoCodes.map((code) => (
                        <tr key={code.code} className="hover:bg-slate-50 transition-colors">
                          <td className="px-8 py-4 font-mono font-bold text-primary">{code.code}</td>
                          <td className="px-6 py-4">
                            {code.is_used ? (
                              <span className="px-3 py-1 bg-red-100 text-red-700 text-[10px] font-bold rounded-full uppercase">Used</span>
                            ) : (
                              <span className="px-3 py-1 bg-emerald-100 text-emerald-700 text-[10px] font-bold rounded-full uppercase">Active</span>
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm text-on-surface-variant">{code.used_at ? new Date(code.used_at).toLocaleDateString("en-GB") : "—"}</td>
                          <td className="px-6 py-4 text-sm font-semibold text-on-surface">{code.used_by || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>


          </div>

          <div className="col-span-1 xl:col-span-5 space-y-8">
            <div className="bg-surface-container-lowest p-8 rounded-3xl shadow-sm">
              <h3 className="text-xl font-bold mb-6">Plan Revenue Share</h3>
              <div className="space-y-6">
                <div>
                  <div className="flex justify-between text-xs font-bold uppercase tracking-wider mb-2">
                    <span className="text-on-surface-variant">
                      Enterprise Plus
                    </span>
                    <span className="text-primary">$2,046,898 (62%)</span>
                  </div>
                  <div className="h-2 bg-surface-container rounded-full overflow-hidden">
                    <div className="h-full bg-primary rounded-full w-[62%]"></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AdminSubscription;
