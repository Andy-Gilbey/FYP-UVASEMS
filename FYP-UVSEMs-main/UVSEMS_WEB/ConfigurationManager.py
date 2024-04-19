from cryptography.fernet import Fernet

class Configurations:
    def __init__(self):
        self.loadConfiguration()
        self.loadKeyBankConfiguration()

    def decryptConfiguration(self):
        with open("encryption.key", "rb") as keyFile:
            key = keyFile.read()

        cipherSuite = Fernet(key)

        with open("encrypted_configuration.enc", "rb") as encryptedFile:
            encryptedData = encryptedFile.read()

        decryptedData = cipherSuite.decrypt(encryptedData)
        return decryptedData.decode("utf-8")

    def decryptKeyBankConfiguration(self):
        with open("encryption_iok.key", "rb") as keyFile:
            key = keyFile.read()
        cipherSuite = Fernet(key)
        with open("encrypted_configuration_iok.enc", "rb") as encryptedFile:
            encryptedData = encryptedFile.read()
        decryptedData = cipherSuite.decrypt(encryptedData)
        decodedData = decryptedData.decode("utf-8")
        # print("Decrypted KeyBank Configuration: ", decodedData)

        return decodedData

    def loadConfiguration(self):
        print("Loading KeyBank configuration from 'encrypted_configuration_iok.enc'")
        configString = self.decryptConfiguration()
        if not configString:
            print("Configuration loading failed.")
            return

        configLines = configString.split("\n")

        config = {}
        for line in configLines:
            if line:
                key, value = line.split("=")
                cleanValue = value.strip().strip(
                    '"'
                )  
                config[key.strip()] = cleanValue

        self.host = config.get("host")
        self.port = int(config.get("port"))
        self.user = config.get("user")
        self.password = config.get("password")
        self.database = config.get("database")

    def loadKeyBankConfiguration(self):
        configString = self.decryptKeyBankConfiguration()
        if not configString:
            print("KeyBank configuration loading failed.")
            return

        configLines = configString.split("\n")
        config = {}
        for line in configLines:
            if line:
                key, value = line.split("=")
                cleanValue = value.strip().strip(
                    '"'
                )  
                config[key.strip()] = cleanValue

        self.keyBankHost = config.get("host")
        self.keyBankPort = int(config.get("port"))
        self.keyBankUser = config.get("user")
        self.keyBankPassword = config.get("password")
        self.keyBankDatabase = config.get("database")
        print(
            f"KeyBank Config: Host: {self.keyBankHost}, User: {self.keyBankUser}, Port: {self.keyBankPort}, Password: {self.keyBankPassword}"
        )
