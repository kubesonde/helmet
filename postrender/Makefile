all: 
	go build -o postrender
	chmod +x postrender

clean: stop
	rm -rf output_dir
	rm postrender

stop: 
	kubectl delete -f output_dir
