# python3-simple-proxy
simple proxy script with api authentication
Needs pass.txt file
username:bcryptpasswordHash
optional
server.pem for https
#curl --header "username: wartak" --header "password: hallo123" http://192.168.178.58:9004/?url=https://google.com
#Invoke-WebRequest -Uri "http://192.168.178.40:9004/?url=https://google.com" -Method GET -Headers @{"username"="wartak";"password"="hallo123"}
#http://[IP]:6004?url=[target_url]
#https://[IP]:1337?url=[target_url]
