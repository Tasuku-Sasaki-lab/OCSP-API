# OCSPーAPI
 
証明書管理画面（https://github.com/Tasuku-Sasaki-lab/Verify-Admin) と同じDBに接続し、証明書の状態を返す
 
 
 
# Features
 
OCSP（ RFC6960)に準拠。
server.py がサーバー側
client.py がクライアント側

サーバー側を立ち上げておいて、外部プログラムからクライアント側を呼び出すことを想定している。
クライアントは、OCSPResponse　もしくは、エラーを外部プログラムに返す
 
# Requirement
 
* Python 3.9
 
# Installation
 
```bash
git clone git@github.com:Tasuku-Sasaki-lab/OCSP-API.git
cd OCSP-API
pip install -r requirements.txt
```
 
# Usage
 
DEMOの実行方法など、"hoge"の基本的な使い方を説明する
.env
```bash
python server.py
MONGO_URL = "mongodb://localhost:27017"
ISSUER_CERT_PATH_SERVER="depot/ca.pem"
ISSUER_KEY_PATH_SERVER="depot/ca.key"
RESPONDER_URL="http://localhost:8000/ocsp"
CERT_PATH_CLIENT="depot/nssdc.crt"
ISSUER_CERT_PATH_CLIENT="depot/ca.pem"
```
 
サーバー側
```bash
source .env
python server.py

```

クライアント側
```bash
python server.py

```
 

 
# DB構造

 #### devices :
 
```bash
	
	devicesSchema = new Schema({
    csrGroup:{type:Number,reqiured:true},
    CN:{type:String,reqiured:true},
    email:{type:Array,reqiured:true},
    type:{type:String,reqiured:true},
    secret:{type:String,reqiured:true},
    status:{type:String,reqiured:true},
    expiration_date:{type:Date,required:true},
    pem:{type:String},
    command:{type:String},
    serial:{type:Number},
    cert_not_before:{type:Date},
    cert_not_after:{type:Date},
});

	
```
 
# Author

* Tasuku Sasaki

*  株式会社　プロキューブ

* t.sasaki.revol@gmail.com
 

 
