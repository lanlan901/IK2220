poxdir ?= /opt/pox/
OUT_LOG_CTRL_PLANE="./results/output_app.txt"
OUT_LOG_TEST_RESULT="./results/output_test_prog.txt"

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	sudo python ./topology/topology.py

app:
	@echo "starting the baseController!"
	sudo cp ./applications/sdn/* /opt/pox/ext
	sudo cp ./applications/nfv/* /opt/pox/ext
	mkdir -p /opt/pox/ext/results
	cd $(poxdir) && python ./pox.py baseController 2>&1 | tee ${OUT_LOG_CTRL_PLANE} &

test:
	@echo "starting test scenarios!"
	make app
	sudo python ./topology/topology_test.py 2>&1 | tee ${OUT_LOG_TEST_RESULT}

clean:
	@echo "project files removed from pox directory!"
	sudo mn --link=tc --topo=mytopo
	sudo killall click
	kill $(shell sudo lsof -t -i:8080)
	sudo cp /opt/pox/ext/results/* ./results
<<<<<<< HEAD
=======



>>>>>>> b8633abe3b479432d03555df929a058d96a2c112
