namespace CredentialManager.Constants
{
    public static class Constants
    {
        /// <summary>
        /// Sets the appname log
        /// </summary>
        public static string EventLogName = "Application";

        /// <summary>
        /// Gets the eventlog application source 
        /// </summary>
        public static string EventLogSource = "CredentialManager";

        /// <summary>
        /// Gets the eventlog eventId
        /// </summary>
        public static short EventLogEventId = 150;

        /// <summary>
        /// Gets the eventlog category services
        /// </summary>
        public static short EventLogCategoryNone = 0;

        /// <summary>
        /// Sets the maximum login attempts
        /// </summary>
        public static int? MaximumLoginAttempts = 5;

        /// <summary>
        /// Sets the login faild locked hours
        /// </summary>
        public static double LockedMinutes = -30;
    }
}