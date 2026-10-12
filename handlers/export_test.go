package handlers

// For the regression tests that make AllocateAddress and RunInstances
// derive an IP already held.
func EC2DeriveEIP(allocID string) string { return ec2DerivePublicIP(ec2EIPNet, allocID) }

func EC2DeriveAutoIP(eniID string) string { return ec2DerivePublicIP(ec2AutoIPNet, eniID) }

// For recorder_test.go's test routes, which mark a class.
var MarkClass = markClass

type RequestClass = requestClass

const ClassUnimplemented = classUnimplemented

// For recorder_test.go's check that every landed service has a protocol.
var ServiceProtocols = serviceProtocols

// For ssm_test.go's sweep of every SSM operation.
var SSMOperations = ssmOperations
