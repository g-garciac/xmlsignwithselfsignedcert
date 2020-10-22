using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace XMLSignaturePoc
{
    public static class SigningXml
    {
        public static string Sign(XmlDocument document, byte[] pkcs12Data, string passwordPkcs12)
        {
            using var certificate = new X509Certificate2(pkcs12Data, passwordPkcs12);
            try
            {
                var rsa = certificate.GetRSAPrivateKey();
                var signedXml = new SignedXml(document)
                {
                    SigningKey = rsa
                };
                var env = new XmlDsigEnvelopedSignatureTransform();
                var reference = new Reference
                {
                    Uri = string.Empty
                };
                reference.AddTransform(env);
                var keyInfo = new KeyInfo();
                var kdata = new KeyInfoX509Data(certificate);
                var xserial = new X509IssuerSerial
                {
                    IssuerName = certificate.Issuer,
                    SerialNumber = certificate.SerialNumber
                };
                kdata.AddIssuerSerial(xserial.IssuerName, xserial.SerialNumber);
                keyInfo.AddClause(kdata);
                signedXml.KeyInfo = keyInfo;
                signedXml.AddReference(reference);
                signedXml.ComputeSignature();
                var xmlDigitalSignature = signedXml.GetXml();
                var xmlNodo = xmlDigitalSignature as XmlNode;
                document.DocumentElement.AppendChild(document.ImportNode(xmlNodo, true));
                return document.OuterXml;
            }
            finally
            {
                certificate.Dispose();
            }
        }
    }
}
