# SaveScanAPI_QuantumCrypto

C:\Users\Samee>curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"username\":\"admin\"}"
{
  "message": "Login successful",
  "signature": "4a6665ee69d3dc034f826f60e7111196dbba770fa3b9880438166e1cf323fc45836929897e62514a75eca0fc501189ac6f5be3fd3c827cec46ad4f158aab78c30bdf35532d1ef76108c77927b82b0493461e05d95447f4ad67d00dc4446ff49a9d93bce155fd9236de79c6a1f749532c67f4f59a3d870f33f618a95de52570e69b8625a9d3c69ca1341cb7c15059a7e06c962dc6e7a91c2493956c43971c63258e8e9daf7f2311093b417e6e5742aba342564ba4a62534b1db605655c03d3d4f091513b0bab6d961f1abf4ca5e99413138239fd585505a07ed284265b27d89f22c11789a52bd96c7acc0d84701107264154da833baa8c961b2a0fbbb5543ace9"
}

C:\Users\Samee>curl -X POST http://localhost:5000/verify -H "Content-Type: application/json" -d "{\"signature\":\"<signature_from_previous_response>\"}"
The system cannot find the file specified.

C:\Users\Samee>curl -X POST http://localhost:5000/verify -H "Content-Type: application/json" -d "{\"signature\":\"4a6665ee69d3dc034f826f60e7111196dbba770fa3b9880438166e1cf323fc45836929897e62514a75eca0fc501189ac6f5be3fd3c827cec46ad4f158aab78c30bdf35532d1ef76108c77927b82b0493461e05d95447f4ad67d00dc4446ff49a9d93bce155fd9236de79c6a1f749532c67f4f59a3d870f33f618a95de52570e69b8625a9d3c69ca1341cb7c15059a7e06c962dc6e7a91c2493956c43971c63258e8e9daf7f2311093b417e6e5742aba342564ba4a62534b1db605655c03d3d4f091513b0bab6d961f1abf4ca5e99413138239fd585505a07ed284265b27d89f22c11789a52bd96c7acc0d84701107264154da833baa8c961b2a0fbbb5543ace9\"}"
{
  "status": "Signature valid"
}

C:\Users\Samee>
