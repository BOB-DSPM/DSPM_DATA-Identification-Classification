pub struct SecretsManagerCollector;  // list_secrets()
pub struct ParamStoreCollector;      // ssm::describe_parameters()
pub struct KmsCollector;             // list_keys/describe_key() (데이터 자체 X, 키 메타)