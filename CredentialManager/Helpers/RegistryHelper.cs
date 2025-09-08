using System;
using Microsoft.Win32;

namespace CredentialManager.Helpers
{
    /// <summary>
    /// helper class registry
    /// </summary>
    public class RegistryHelper
    {
        /// <summary>
        /// get registry key
        /// </summary>
        /// <returns></returns>
        public static RegistryKey GetRegistryKey()
        {
            return GetRegistryKey(null);
        }

        /// <summary>
        /// override get registry key
        /// </summary>
        /// <param name="keyPath"></param>
        /// <returns></returns>
        public static RegistryKey GetRegistryKey(string keyPath)
        {
            RegistryKey localMachineRegistry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32);

            return string.IsNullOrEmpty(keyPath)
                ? localMachineRegistry
                : localMachineRegistry.OpenSubKey(keyPath);
        }

        /// <summary>
        /// get registry value
        /// </summary>
        /// <param name="keyPath"></param>
        /// <param name="keyName"></param>
        /// <returns></returns>
        public static object GetRegistryValue(string keyPath, string keyName)
        {
            RegistryKey registry = GetRegistryKey(keyPath);
            return registry.GetValue(keyName);
        }
    }
}