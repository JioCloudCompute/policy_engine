# policy_engine_modified

This is the policy engine which would be used for creating list of action-resource-implicit_allow tuples. 

This list is sent to IAM for authorization. The module is not a middleware. The middleware which calls IAM in any JCS
frontend would be responsible for initializing the module and retrieving the list of tuples from it.

Added a mapping.json as sample file.
