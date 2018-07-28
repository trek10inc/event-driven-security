# AWS Config Rule Settings:

# Trigger type = Configuration changes
# Resources = Lambda:Function, EC2:Instance

# Key: port1, Value: [portNumber] e.g. 80 and or
# Key: port2, Value: [portRange]  e.g. 0-1024

import boto3
import json
import sets

APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup", "AWS::Lambda::Function"]
lambda_client = boto3.client('lambda')

# Given a SecurityGroup, find the related Functions...
def functionsForSecurityGroupId( secGroupId ):
	return [ f for f in lambda_client.list_functions()['Functions'] if 'VpcConfig' in f and secGroupId in f['VpcConfig']['SecurityGroupIds']]

# Given a function find its security groups...
def secGroupsForFunction(func_name):
	f = lambda_client.get_function(FunctionName=func_name)['Configuration']
	return f['VpcConfig']['SecurityGroupIds'] if 'VpcConfig' in f else []

# Given a trigger security group, determine all the unique sec groups
# that need to be evaluated, and determine the relationships to functions.
def determineEvaluationScopeFromTriggerSecGroup( triggerSecGroup ):
	functionsToEvaluate = {}
	secGroupsToCheck = set()
	for function in functionsForSecurityGroupId(triggerSecGroup):
		functionsToEvaluate[function['FunctionName']] = []
		for group in secGroupsForFunction(function['FunctionName']):
			functionsToEvaluate[function['FunctionName']].append(group)
			secGroupsToCheck.add(group)
	return { 'functionsToEvaluate' : functionsToEvaluate, 
			 'secGroupsToCheck' : secGroupsToCheck }

# Determine the exposed ports from the ip permissions of a security group
def find_exposed_ports(ip_permissions):
	exposed_ports = []
	for permission in ip_permissions or []:
		for ip in permission["IpRanges"]:
			if "0.0.0.0/0" in ip['CidrIp']:
				exposed_ports.extend(range(permission["FromPort"],
										   permission["ToPort"]+1))
	return exposed_ports

def expand_range(ports):
    if "-" in ports:
        return range(int(ports.split("-")[0]), int(ports.split("-")[1])+1)
    else:
        return [int(ports)]

def find_violation(exposed_ports, forbidden_ports):
	for forbidden in forbidden_ports:
		ports = expand_range(forbidden_ports[forbidden])
		for port in ports:
			if port in exposed_ports:
				return True

	return False

def getViolationGroups( secGroupSet, forbiddenPorts ):
	violations = []
	for secGroup in secGroupSet:
		ec2 = boto3.resource('ec2')
		security_group = ec2.SecurityGroup(secGroup)
		exposed_ports = find_exposed_ports( security_group.ip_permissions ) 
		if find_violation( exposed_ports, forbiddenPorts):
			violations.append(secGroup)

	return violations

def evaluate_compliance(configuration_item, rule_parameters):
	violationFunctions = {}
	
	if configuration_item["resourceType"] == "AWS::EC2::SecurityGroup":
		if ( configuration_item["configuration"] ):
			triggerSecGroupId = configuration_item["configuration"]["groupId"]
			scope = determineEvaluationScopeFromTriggerSecGroup( triggerSecGroupId )
		else:
			return False
			
	elif configuration_item["resourceType"] == "AWS::Lambda::Function":
		function_name = configuration_item["configuration"]["functionName"]
		groups = secGroupsForFunction( function_name )
		groupSet = set()
		for group in groups:
			groupSet.add(group)
		scope = { "secGroupsToCheck" : groupSet,
				  "functionsToEvaluate" : { function_name : groupSet } }
	else:
		return False
	
	functionsToEvaluate = scope['functionsToEvaluate']	
	violationGroups = getViolationGroups( scope['secGroupsToCheck'], rule_parameters )

	for f in functionsToEvaluate:
		violationFunctions[f] = []
		for group in violationGroups:
			if group in functionsToEvaluate[f]:
				violationFunctions[f].append(group)

	return violationFunctions

def lambda_handler(event, context):

	#print( json.dumps(event) )

	invoking_event = json.loads(event["invokingEvent"])
	configuration_item = invoking_event["configurationItem"]
	rule_parameters = json.loads(event["ruleParameters"])

	result_token = "No token found."
	if "resultToken" in event:
		result_token = event["resultToken"]

	outputEvaluation = []

	evaluations = evaluate_compliance(configuration_item, rule_parameters)
	
	if evaluations:
		for evaluation in evaluations:	
			if (len( evaluations[evaluation] )):
				outputEvaluation.append ({
					"ComplianceResourceType": "AWS::Lambda::Function",
					"ComplianceResourceId": evaluation,
					"ComplianceType": "NON_COMPLIANT",
					"Annotation": "Function has non compliant groups {}".format( ','.join(evaluations[evaluation]) ),
					"OrderingTimestamp": configuration_item["configurationItemCaptureTime"]
				})
			else:
				outputEvaluation.append ({
					"ComplianceResourceType": "AWS::Lambda::Function",
					"ComplianceResourceId": evaluation,
					"ComplianceType": "COMPLIANT",
					"Annotation": "This resource is compliant with the rule.",
					"OrderingTimestamp": configuration_item["configurationItemCaptureTime"]
				})
	
	else:
		outputEvaluation.append ({
			"ComplianceResourceType": configuration_item["resourceType"],
			"ComplianceResourceId": configuration_item["resourceId"],
			"ComplianceType": "NOT_APPLICABLE",
			"Annotation": "The rule doesn't apply to resources of type {} or this resource {} has been deleted.".format( configuration_item["resourceType"], configuration_item["resourceId"] ),
			"OrderingTimestamp": configuration_item["configurationItemCaptureTime"]
		})
	
	print (json.dumps(outputEvaluation))

	config = boto3.client("config")
	result = config.put_evaluations(
		Evaluations=outputEvaluation,
		ResultToken=result_token
	)