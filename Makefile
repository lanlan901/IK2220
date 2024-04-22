poxdir ?= /opt/pox/
OUT_LOG_CTRL_PLANE="/opt/IK2220/results/output_app.txt"
OUT_LOG_TEST_RESULT="/opt/IK2220/results/output_test_prog.txt"

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	# 为 ws1 设置端口转发
	sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -d 100.0.0.40 -j DNAT --to-destination 100.0.0.40:8080
	sudo iptables -t nat -A POSTROUTING -p tcp -d 100.0.0.40 --dport 8080 -j MASQUERADE

	# 为 ws2 设置端口转发
	sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -d 100.0.0.41 -j DNAT --to-destination 100.0.0.41:8080
	sudo iptables -t nat -A POSTROUTING -p tcp -d 100.0.0.41 --dport 8080 -j MASQUERADE

	# 为 ws3 设置端口转发
	sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -d 100.0.0.42 -j DNAT --to-destination 100.0.0.42:8080
	sudo iptables -t nat -A POSTROUTING -p tcp -d 100.0.0.42 --dport 8080 -j MASQUERADE

	sudo python /opt/IK2220/topology/topology.py

app:
	@echo "starting the baseController!"
	sudo cp -r /opt/IK2220/applications/sdn/* /opt/pox/ext
	sudo cp -r /opt/IK2220/applications/nfv/* /opt/pox/ext
	mkdir -p /opt/pox/ext/results
	cd $(poxdir) && python ./pox.py log.level --DEBUG baseController 2>&1 | tee ${OUT_LOG_CTRL_PLANE} &

test:
	@echo "starting test scenarios!"
	make app
	make topo
	sudo python ./topology/topology_test.py 2>&1 | tee ${OUT_LOG_TEST_RESULT}

clean:
	@echo "project files removed from pox directory!"
	sudo mn --link=tc --topo=mytopo
	kill $(shell sudo lsof -t -i:8080)
	kill $(shell sudo lsof -t -i:6633)
	sudo cp /opt/pox/ext/results/* ./results
