package handlers

// For the regression test that makes AllocateAddress derive an IP
// already held.
var EC2DerivePublicIP = ec2DerivePublicIP

// For recorder_test.go's test routes, which mark a class.
var MarkClass = markClass

type RequestClass = requestClass

const ClassUnimplemented = classUnimplemented

// For recorder_test.go's check that every landed service has a protocol.
var ServiceProtocols = serviceProtocols
