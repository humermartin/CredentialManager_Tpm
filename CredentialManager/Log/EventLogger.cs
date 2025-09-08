using log4net;
using System;
using System.Diagnostics;
using System.Reflection;

namespace CredentialManager.Log
{
    /// <summary>
    /// class event logger
    /// </summary>
    public class EventLogger
    {
        /// <summary>
        /// log4net setter
        /// </summary>
        protected static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Writes message to event viewer
        /// </summary>
        /// <param name="strErrDetail"></param>
        /// <param name="entryType"></param>
        public static void WriteToLog(string strErrDetail, EventLogEntryType entryType)
        {
            try
            {
                //Step 1: write to log4net
                switch (entryType)
                {
                    case EventLogEntryType.Information:
                        Log.Info(strErrDetail);
                        break;

                    case EventLogEntryType.Error:
                        Log.Error(strErrDetail);
                        break;
                }

                //Step 2: write to eventlog
                if (!EventLog.SourceExists(Constants.Constants.EventLogSource))
                {
                    EventLog.CreateEventSource(Constants.Constants.EventLogSource, Constants.Constants.EventLogName);
                }

                // Create an EventLog instance and assign its source.
                EventLog eventLog = new EventLog(Constants.Constants.EventLogName);
                eventLog.Source = Constants.Constants.EventLogSource;
                eventLog.Log = Constants.Constants.EventLogName;
                
                eventLog.WriteEntry(strErrDetail, entryType, Constants.Constants.EventLogEventId, Constants.Constants.EventLogCategoryNone);
                eventLog.Dispose();

                
            }
            catch (Exception ex)
            {
                Log.Error($"{MethodBase.GetCurrentMethod().Name}. Error: {ex.Message}");
            }
            
        }

    }
}