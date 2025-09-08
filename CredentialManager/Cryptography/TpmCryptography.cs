using log4net;
using System;
using System.Reflection;
using Tpm2Lib;

namespace CredentialManager.Cryptography
{
    public class TpmCryptography
    {
        /// <summary>
        /// Member which holds the log4net logger
        /// </summary>
        protected static readonly ILog Log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);


        /// <summary>
        /// creates tpm rsa primary key
        /// </summary>
        /// <param name="tpm"></param>
        /// <returns></returns>
        public TpmHandle CreateRsaPrimaryKey(Tpm2 tpm)
        {
            try
            {
                var sensCreate = new SensitiveCreate();

                SymDefObject symDefObject = new SymDefObject();
                NullAsymScheme asymScheme = new NullAsymScheme();
                RsaParms rsParam = new RsaParms(symDefObject, asymScheme, 2048, 0);
                Tpm2bPublicKeyRsa publicKeyRsa = new Tpm2bPublicKeyRsa();

                //Create a key template first
                TpmPublic parms = new TpmPublic(TpmAlgId.Sha384, ObjectAttr.Decrypt | ObjectAttr.Sign | ObjectAttr.FixedParent | ObjectAttr.FixedTPM | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin, null, rsParam, publicKeyRsa);

                byte[] outsideInfo = Globs.GetRandomBytes(8);
                var creationPcr = new PcrSelection(TpmAlgId.Sha384, new uint[] { 0, 1, 2 });

                TpmPublic pubCreated;
                CreationData creationData;
                TkCreation creationTicket;
                byte[] creationHash;

                //Create a key using the template
                TpmHandle h = tpm.CreatePrimary(TpmRh.Owner,
                    sensCreate,
                    parms,
                    outsideInfo,
                    new PcrSelection[] { creationPcr },
                    out pubCreated,
                    out creationData,
                    out creationHash,
                    out creationTicket);

                return h;
            }
            catch (Exception ex)
            {
                Log.Error($"{MethodBase.GetCurrentMethod()?.Name}. {ex.Message}, {ex.InnerException}");
                throw;
            }
            
        }
        

        //Helper methods to work with strings and bytes
        public static byte[] StringToByteArray(string str)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            return enc.GetBytes(str);
        }

        public static string ByteArrayToString(byte[] arr)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            return enc.GetString(arr);
        }

        /// <summary>
        /// encrypt plain key
        /// </summary>
        /// <param name="keyPass"></param>
        /// <returns></returns>
        public string EncryptKey(string keyPass)
        {
            //connect to default tpm device
            Tpm2Device tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            var tpm = new Tpm2(tpmDevice);
            
            TpmHandle primHandle = CreateRsaPrimaryKey(tpm);

            IAsymSchemeUnion decScheme = new SchemeOaep(TpmAlgId.Sha384);
            
            byte[] encrypted = tpm.RsaEncrypt(primHandle, StringToByteArray(keyPass), decScheme, null);

            tpm.Dispose();

            string encryptedKey = Convert.ToBase64String(encrypted);
            
            return encryptedKey;
        }

        /// <summary>
        /// decrypt key to plain
        /// </summary>
        /// <param name="codedFile"></param>
        /// <returns></returns>
        public string DecryptKey(string codedFile)
        {
            //decrypt data
            Tpm2Device tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            var tpm = new Tpm2(tpmDevice);
            
            TpmHandle primHandle = CreateRsaPrimaryKey(tpm);
            IAsymSchemeUnion decScheme = new SchemeOaep(TpmAlgId.Sha384);
            
            var decrypted = tpm.RsaDecrypt(primHandle, Convert.FromBase64String(codedFile), decScheme, null);
            string decryptedKey = ByteArrayToString(decrypted);

            tpm.Dispose();

            return decryptedKey;
        }
    }
}
