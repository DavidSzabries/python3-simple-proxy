# python3-simple-proxy
simple proxy script with api authentication

Needs pass.txt file

username:bcryptpasswordHash

optional

server.pem for https

register user:

curl -X POST  --header "setuser: test123" --header "setpwd: test123" http://192.168.178.58:5000/register

#curl --header "username: test" --header "password: test123" http://192.168.178.58:9004/?url=https://google.com
#Invoke-WebRequest -Uri "http://192.168.178.40:9004/?url=https://google.com" -Method GET -Headers @{"username"="test";"password"="test123"}

#http://[IP]:6004?url=[target_url]

#https://[IP]:13037?url=[target_url]
