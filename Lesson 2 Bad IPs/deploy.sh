aws cloudformation package --template-file website.yaml --output-template-file website-out.yaml --s3-bucket serverless-deployments-us-east-1-491142528373
aws cloudformation deploy --template-file ./website-out.yaml --stack-name cguse-website --capabilities CAPABILITY_IAM
aws s3 cp ./index.html s3://serverless-deployments-us-east-1-491142528373