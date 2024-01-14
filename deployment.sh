#! /bin/sh

###########
## Usage: 
###########
file=deployment.yaml
imagePath='IMAGE_PATH'
deployName='DEPLOY_NAME'
new_imagePath=$1
new_deployName=$2

echo "Changing the IMAGE_PATH to $imagePath"

sed -i "s|$imagePath|$new_imagePath|g" $file
sed -i "s|$deployName|$new_deployName|g" $file

echo "Catting the $file"

cat deployment.yaml

echo "Shell script finished"

