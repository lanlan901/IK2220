poxdir = /opt/pox/
OUT_LOG_CTRL_PLANE="../results/output_app.txt"
OUT_LOG_TEST_RESULT="../results/output_test_prog.txt"

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	sudo python topology/topology.py

app:

	@echo "starting the baseController!"
	sudo cp -r ./applications/sdn/* $(poxdir)ext
	sudo cp -r ./applications/nfv/* $(poxdir)ext
	mkdir -p $(poxdir)ext/results
	cd $(poxdir) && python ./pox.py log.level --DEBUG baseController 2>&1 | tee ${OUT_LOG_CTRL_PLANE} &
#	cd $(poxdir) && python ./pox.py baseController 2>&1 | tee ${OUT_LOG_CTRL_PLANE} &

test:
	@echo "starting test scenarios!"
	make app
	sleep 5 
	sudo python ./topology/topology_test.py 2>&1 | tee ${OUT_LOG_TEST_RESULT}

clean:
	@echo "project files removed from pox directory!"
	sudo rm -rf ../pox/ext/*
	sudo mn --link=tc --topo=mytopo
	sudo killall click
	kill $(shell sudo lsof -t -i:8080)
	kill $(shell sudo lsof -t -i:6633)
	sudo cp ../pox/ext/results/* ./results