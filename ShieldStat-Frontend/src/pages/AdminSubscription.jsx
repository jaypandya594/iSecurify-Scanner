import React, { useState, useEffect } from "react";
import { generatePromoCode, getPromoCodes } from "../services/api";

const INITIAL_PLANS = [
   {
      id: "enterprise-plus",
      name: "Enterprise Plus",
      price: 499,
      icon: "rocket_launch",
      color: "primary",
      containerColor: "primary-container",
      popular: true,
      features: ["Unlimited Scans", "Priority Support", "Custom Integrations"],
   },
   {
      id: "business-pro",
      name: "Business Pro",
      price: 199,
      icon: "business_center",
      color: "tertiary",
      containerColor: "tertiary-container",
      popular: false,
      features: ["Advanced Analytics", "Team Management", "API Access"],
   },
   {
      id: "standard",
      name: "Standard",
      price: 49,
      icon: "work",
      color: "secondary",
      containerColor: "secondary-container",
      popular: false,
      features: ["Basic Scanning", "Email Support", "Monthly Reports"],
   },
   {
      id: "free-tier",
      name: "Free Tier",
      price: 0,
      icon: "hourglass_top",
      color: "outline-variant",
      containerColor: "outline-variant",
      popular: false,
      features: ["5 Scans/Month", "Basic Reports", "Community Support"],
   },
];

function AdminSubscription() {
   const [promoCodes, setPromoCodes] = useState([]);
   const [promoLoading, setPromoLoading] = useState(false);
   const [generatingPromo, setGeneratingPromo] = useState(false);
   const [notification, setNotification] = useState({ text: "", type: "" });
   const [plans, setPlans] = useState(INITIAL_PLANS);
   const [editingPlanId, setEditingPlanId] = useState(null);
   const [editingData, setEditingData] = useState(null);
   const [savingPlan, setSavingPlan] = useState(false);

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

   const handleEditPlan = (planId) => {
      const plan = plans.find(p => p.id === planId);
      setEditingPlanId(planId);
      setEditingData({ ...plan });
   };

   const handleCancelEdit = () => {
      setEditingPlanId(null);
      setEditingData(null);
   };

   const handlePriceChange = (value) => {
      setEditingData({ ...editingData, price: parseInt(value) || 0 });
   };

   const handleNameChange = (value) => {
      setEditingData({ ...editingData, name: value });
   };

   const handleFeatureChange = (index, value) => {
      const updatedFeatures = [...editingData.features];
      updatedFeatures[index] = value;
      setEditingData({ ...editingData, features: updatedFeatures });
   };

   const handleAddFeature = () => {
      setEditingData({ ...editingData, features: [...editingData.features, ""] });
   };

   const handleRemoveFeature = (index) => {
      const updatedFeatures = editingData.features.filter((_, i) => i !== index);
      setEditingData({ ...editingData, features: updatedFeatures });
   };

   const handleSavePlan = async () => {
      if (!editingData.name.trim()) {
         showNotification("Plan name cannot be empty", "error");
         return;
      }

      const emptyFeatures = editingData.features.some(f => !f.trim());
      if (emptyFeatures) {
         showNotification("All features must have a description", "error");
         return;
      }

      setSavingPlan(true);
      try {
         // TODO: Add API call to save plan
         // await updatePlan(localStorage.getItem("token"), editingPlanId, editingData);

         const updatedPlans = plans.map(p =>
            p.id === editingPlanId ? editingData : p
         );
         setPlans(updatedPlans);
         showNotification(`${editingData.name} plan updated successfully`);
         setEditingPlanId(null);
         setEditingData(null);
      } catch (err) {
         showNotification(err.message, "error");
      } finally {
         setSavingPlan(false);
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

         <div className="p-10 space-y-10">
            {/* Header */}
            <div className="flex items-end justify-between">
               <div>
                  <h2 className="text-4xl font-black text-on-surface tracking-tight mb-2">
                     Subscription Management
                  </h2>
                  <p className="text-on-surface-variant max-w-md">
                     Define service tiers, adjust pricing models, manage enterprise
                     features, and generate promotional codes.
                  </p>
               </div>
            </div>

            {/* Pricing Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
               {plans.map((plan) => (
                  <div
                     key={plan.id}
                     className={`p-6 rounded-3xl shadow-sm border-2 transition-all relative overflow-hidden group ${editingPlanId === plan.id
                           ? "border-primary/50 bg-primary/5"
                           : plan.popular
                              ? "border-primary/10 bg-surface-container-lowest hover:border-primary/30"
                              : "border-surface-container bg-surface-container-lowest hover:border-primary/30"
                        }`}
                  >
                     {plan.popular && !editingPlanId && (
                        <div className="absolute top-0 right-0 p-4">
                           <span className="px-2 py-1 bg-primary/10 text-primary text-[10px] font-bold rounded-lg uppercase">
                              Popular
                           </span>
                        </div>
                     )}

                     {editingPlanId === plan.id ? (
                        // Edit Mode
                        <div className="space-y-4">
                           <div>
                              <label className="text-xs font-bold uppercase text-on-surface-variant block mb-1">
                                 Plan Name
                              </label>
                              <input
                                 type="text"
                                 value={editingData.name}
                                 onChange={(e) => handleNameChange(e.target.value)}
                                 className="w-full bg-surface-container px-3 py-2 rounded-lg border border-surface-container text-sm font-semibold text-on-surface focus:outline-none focus:border-primary"
                              />
                           </div>

                           <div>
                              <label className="text-xs font-bold uppercase text-on-surface-variant block mb-1">
                                 Price ($/month)
                              </label>
                              <input
                                 type="number"
                                 value={editingData.price}
                                 onChange={(e) => handlePriceChange(e.target.value)}
                                 className="w-full bg-surface-container px-3 py-2 rounded-lg border border-surface-container text-sm font-semibold text-on-surface focus:outline-none focus:border-primary"
                                 min="0"
                              />
                           </div>

                           <div>
                              <label className="text-xs font-bold uppercase text-on-surface-variant block mb-2">
                                 Features
                              </label>
                              <div className="space-y-2 mb-3 max-h-32 overflow-y-auto">
                                 {editingData.features.map((feature, idx) => (
                                    <div key={idx} className="flex items-center gap-2">
                                       <input
                                          type="text"
                                          value={feature}
                                          onChange={(e) => handleFeatureChange(idx, e.target.value)}
                                          placeholder="Feature description"
                                          className="flex-1 bg-surface-container px-2 py-1 rounded text-xs border border-surface-container focus:outline-none focus:border-primary"
                                       />
                                       <button
                                          onClick={() => handleRemoveFeature(idx)}
                                          className="p-1 text-red-500 hover:bg-red-100 rounded transition-all"
                                       >
                                          <span className="material-symbols-outlined text-sm">close</span>
                                       </button>
                                    </div>
                                 ))}
                              </div>
                              <button
                                 onClick={handleAddFeature}
                                 className="text-xs font-semibold text-primary hover:text-primary-dim transition-all flex items-center gap-1"
                              >
                                 <span className="material-symbols-outlined text-sm">add</span>
                                 Add Feature
                              </button>
                           </div>

                           <div className="flex gap-2 pt-4 border-t border-surface-container">
                              <button
                                 onClick={handleCancelEdit}
                                 className="flex-1 px-3 py-2 bg-surface-container text-on-surface rounded-lg font-semibold text-xs hover:bg-surface-container-low transition-all"
                              >
                                 Cancel
                              </button>
                              <button
                                 onClick={handleSavePlan}
                                 disabled={savingPlan}
                                 className="flex-1 px-3 py-2 bg-primary text-white rounded-lg font-semibold text-xs hover:bg-primary-dim transition-all disabled:opacity-50 flex items-center justify-center gap-1"
                              >
                                 {savingPlan ? (
                                    <span className="material-symbols-outlined text-sm animate-spin">refresh</span>
                                 ) : (
                                    <span className="material-symbols-outlined text-sm">check</span>
                                 )}
                                 Save
                              </button>
                           </div>
                        </div>
                     ) : (
                        // View Mode
                        <>
                           <button
                              onClick={() => handleEditPlan(plan.id)}
                              className="absolute bottom-4 right-4 w-10 h-10 rounded-full bg-primary/10 text-primary hover:bg-primary/20 transition-all z-10 flex items-center justify-center"
                              title="Edit plan"
                           >
                              <span className="material-symbols-outlined text-sm">edit</span>
                           </button>

                           <div className="flex justify-start mb-6">
                              <div className="w-12 h-12 rounded-2xl bg-opacity-30 flex items-center justify-center text-primary">
                                 <span className="material-symbols-outlined">{plan.icon}</span>
                              </div>
                           </div>

                           <h3 className="text-xl font-black text-on-surface mb-1">
                              {plan.name}
                           </h3>
                           <p className="text-3xl font-black text-primary mb-4">
                              ${plan.price}
                              <span className="text-sm font-medium text-on-surface-variant">
                                 {plan.price > 0 ? "/mo" : ""}
                              </span>
                           </p>
                           <div className="space-y-2">
                              {plan.features.map((feature, idx) => (
                                 <div key={idx} className="flex items-center gap-2 text-xs font-medium text-on-surface-variant">
                                    <span className="material-symbols-outlined text-emerald-500 text-sm">
                                       check_circle
                                    </span>
                                    {feature}
                                 </div>
                              ))}
                           </div>
                        </>
                     )}
                  </div>
               ))}
            </div>

            {/* Promo Codes & Editor Config */}
            <div className="grid grid-cols-12 gap-8">
               <div className="col-span-12 xl:col-span-7 space-y-8">
                  <div className="bg-surface-container-lowest rounded-3xl overflow-hidden shadow-sm">
                     <div className="px-8 py-6 flex items-center justify-between border-b border-surface-container">
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

               <div className="col-span-12 xl:col-span-5 space-y-8">
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
