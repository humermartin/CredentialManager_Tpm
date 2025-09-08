using System.Web.Optimization;

namespace CredentialManager
{
    public class BundleConfig
    {
        // For more information on bundling, visit https://go.microsoft.com/fwlink/?LinkId=301862
        public static void RegisterBundles(BundleCollection bundles)
        {
            bundles.Add(new ScriptBundle("~/bundles/jquery").Include(
                "~/Scripts/jquery-{version}.js",
                "~/Scripts/jquery-ui.min.js"));

            bundles.Add(new ScriptBundle("~/bundles/jqueryval").Include(
                        "~/Scripts/jquery.validate*"));

            bundles.Add(new ScriptBundle("~/bundles/kendo").Include(
                "~/Scripts/kendo/2019.1.220/kendo.all.min.js",
                "~/Scripts/kendo/2019.1.220/kendo.web.min.js"));
            
            // Use the development version of Modernizr to develop with and learn from. Then, when you're
            // ready for production, use the build tool at https://modernizr.com to pick only the tests you need.
            bundles.Add(new ScriptBundle("~/bundles/modernizr").Include(
                        "~/Scripts/modernizr-*"));

            bundles.Add(new ScriptBundle("~/bundles/credmanager").Include(
                "~/Scripts/credmanager.js"));

            bundles.Add(new ScriptBundle("~/bundles/bootstrap").Include(
                      "~/Scripts/bootstrap.js",
                      "~/Scripts/bootstrap-switch.min.js",
                      "~/Scripts/bootstrap-multiselect.js"));

            bundles.Add(new StyleBundle("~/Content/css").Include(
                "~/Content/jquery-ui.css",
                "~/Content/bootstrap.css",
                "~/Content/bootstrap-multiselect.css",
                "~/Content/bootstrap-switch/bootstrap3/bootstrap-switch.min.css",
                "~/Content/site.css",
                "~/Content/kendo/2019.1.220/kendo.common.min.css",
                "~/Content/kendo/2019.1.220/kendo.default.min.css",
                "~/Content/kendo/2019.1.220/kendo.common-bootstrap.min.css",
                "~/Content/kendo/2019.1.220/kendo.rtl.min.css",
                "~/Content/kendo/2019.1.220/kendo.bootstrap.min.css",
                "~/Content/kendo/2019.1.220/kendo.silver.min.css"));
        }
    }
}
