import web
import hashlib
import time

class FileServer:
    def __init__(self):
        self.urls = ("/upload/*", FileAuthenticator)
        self.app = web.application(self.urls, globals())

    def run(self):
        self.app.run()

    def request(self, url):
        return self.app.request(url)

class FileAuthenticator:
    def GET(self):
        upload_data = web.input()
        file_data = upload_data.file
        file_signature = upload_data.signature
        if self.insecure_compare(file_data, file_signature):
            return "File authenticated and uploaded successfully"
        else:
            return web.HTTPError("500")

    def insecure_compare(self, file_data, file_signature):
        hash_verifier = hashlib.md5()
        hash_verifier.update(self.key + file_data.encode("ascii"))
        verification_signature = hash_verifier.digest()
        file_signature = bytearray.fromhex(file_signature)
        if len(file_signature) != len(verification_signature):
            return False
        for idx in range(16):
            if verification_signature[idx] != file_signature[idx]:
                return False
            time.sleep(0.005)
        return True

    @classmethod
    def set_key(cls, key):
        cls.key = key

if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("ascii")
    FileAuthenticator.set_key(key)
    
    fs = FileServer()
    fs.run()
