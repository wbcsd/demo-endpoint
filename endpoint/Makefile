AWS_PROFILE=pathfinder-prod
AWS_REGION=eu-central-1
LAMBDA_NAME=pathfinder-alpha

build-lambda: target_lambda/deploy.zip

target_lambda/deploy.zip:
	docker run -it --rm -v ~/.cargo/registry:/root/.cargo/registry:z -v `pwd`/:/build:z lambda_builder

.PHONY: target/rust.zip
target/rust.zip:
	cargo build --release --target x86_64-unknown-linux-musl
	rm -f $@
	zip -j $@ ./target/x86_64-unknown-linux-musl/release/bootstrap

local-upload: target/rust.zip
	aws --profile=${AWS_PROFILE} lambda update-function-code \
		--function-name ${LAMBDA_NAME} \
		--zip-file fileb://$<  \
		--region ${AWS_REGION}

aws-upload: target_lambda/deploy.zip
	aws --profile=${AWS_PROFILE} lambda update-function-code \
		--function-name ${LAMBDA_NAME} \
		--zip-file fileb://$<  \
		--region ${AWS_REGION}

.PHONY: build-lambda target_lambda/deploy.zip aws-upload
