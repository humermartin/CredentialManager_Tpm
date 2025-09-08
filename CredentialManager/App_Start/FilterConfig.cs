using System.Web.Mvc;
using NWebsec.Mvc.HttpHeaders;
using NWebsec.Mvc.HttpHeaders.Csp;

namespace CredentialManager
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            // handle error attribute
            filters.Add(new HandleErrorAttribute());


            // report only attribute
            filters.Add(new CspReportOnlyAttribute());

            filters.Add(new CspDefaultSrcReportOnlyAttribute 
            {
                // Disallow everything from the same domain by default.
                None = true,
                // Allow everything from the same domain by default.
                // Self = true
            });

            // connect-src - This directive restricts which URIs the protected resource can load using script interfaces 
            //               (Ajax Calls and Web Sockets).
            filters.Add(new CspConnectSrcReportOnlyAttribute()
            {
                // Allow AJAX and Web Sockets to example.com.
                // CustomSources = "example.com",
                // Allow all AJAX and Web Sockets calls from the same domain.
                Self = true
            });

            // font-src - This directive restricts from where the protected resource can load fonts.
            filters.Add(new CspFontSrcReportOnlyAttribute()
            {
                // Allow fonts from example.com.
                // CustomSources = "example.com",
                // Allow all fonts from the same domain.
                Self = true
                
            });

            // form-action - This directive restricts which URLs can be used as the action of HTML form elements.
            filters.Add(new CspFormActionReportOnlyAttribute()
            {
                // Allow forms to post back to example.com.
                // CustomSources = "example.com",
                // Allow forms to post back to the same domain.
                Self = true
            });

            // img-src - This directive restricts from where the protected resource can load images.
            filters.Add(new CspImgSrcReportOnlyAttribute()
            {
                // Allow images from example.com.
                // CustomSources = "example.com",
                // Allow images from the same domain.
                Self = true,
            });

            // script-src - This directive restricts which scripts the protected resource can execute. 
            //              The directive also controls other resources, such as XSLT style sheets, which can cause the user agent to execute script.
            filters.Add(new CspScriptSrcReportOnlyAttribute()
            {
                // Allow scripts from the CDN's.
                CustomSources = string.Format("ajax.googleapis.com ajax.aspnetcdn.com"),
                // Allow scripts from the same domain.
                Self = true,
                // Allow the use of the eval() method to create code from strings. This is unsafe and can open your site up to XSS vulnerabilities.
                // UnsafeEval = true,
                // Allow inline JavaScript, this is unsafe and can open your site up to XSS vulnerabilities.
                // UnsafeInline = true
            });

            // style-src - This directive restricts which styles the user applies to the protected resource.
            filters.Add(new CspStyleSrcReportOnlyAttribute()
            {
                // Allow CSS from example.com
                // CustomSources = "example.com",
                // Allow CSS from the same domain.
                Self = true,
                // Allow inline CSS, this is unsafe and can open your site up to XSS vulnerabilities.
                // Note: This is currently enable because Modernizr does not support CSP and includes inline styles
                // in its JavaScript files. This is a security hold. If you don't want to use Modernizr, 
                // be sure to disable unsafe inline styles. For more information see:
                // http://stackoverflow.com/questions/26532234/modernizr-causes-content-security-policy-csp-violation-errors
                // https://github.com/Modernizr/Modernizr/pull/1263
                UnsafeInline = true
            });

            // The CspViolationReport is a representation of the JSON CSP violation
            // that the browser sends you. It contains several properties, which can tell you about the blocked URL, the violated directive, the user agent and a lot more.
            // This is your opportunity to log this data in your preferred logging framework.
            filters.Add(new CspReportUriReportOnlyAttribute()
            {
                EnableBuiltinHandler = true
            });
            
            //<add name="X-Frame-Options" value="DENY" />
            filters.Add(new XFrameOptionsAttribute()
            {
                Policy = XFrameOptionsPolicy.Deny
            });
        }
    }
}
