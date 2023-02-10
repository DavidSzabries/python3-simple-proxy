# python3 simple HTTP/HTTPS proxy
simple proxy script with api authentication

Needs pass.txt file

username:bcryptpasswordHash

optional

server.pem for https

register user:

curl -X POST  --header "setuser: test123" --header "setpwd: test123" http://[API-IP]:5000/register

Invoke-WebRequest -Method POST -Headers @{'setuser'='test123';'setpwd'='test123'} -Uri 'http://[API-IP]:5000/register'

terminal Usage:

#curl --header "username: test" --header "password: test123" http://[IP]:9004/?url=https://google.com

#Invoke-WebRequest -Uri "http://[IP]:9004/?url=https://google.com" -Method GET -Headers @{"username"="test";"password"="test123"} -OutFile "test.bin"

Browser usage (you need to be able to set headers manual!) :

#http://[IP]:6004?url=[target_url]

#https://[IP]:13037?url=[target_url]

