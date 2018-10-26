# sipflare-proxy
SipFlare is a Node.JS SIP transparent proxy allows secure VoIP communication  
It is designed to mask a SIP server behind this service both on the internet and on an sipflare-proxy accessible private network  
created to be used in conjunction with sipflare-dns allowing SIP proxy DNS management  

Currently supporting four types of SIP Messages:   
- REGISTER: device registration/deregistration  
- OPTIONS: device keep-alive and TTL  
- INVITE: SIP session handling   
- GENERIC: SIP generic message    

Designed to offer performance use a in-memory realtime database (redis) and postgresql    



https://github.com/hoverflow/sipflare-proxy  



