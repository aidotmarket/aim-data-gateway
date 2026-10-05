package deploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	av "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
)

type object = map[string]any

func template(t *testing.T) object {
	t.Helper()
	b, err := os.ReadFile("aws-verifier.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var v object
	// JSON is YAML 1.2; standard-library parsing avoids a runtime YAML module.
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func encoded(v any) string { b, _ := json.Marshal(v); return string(b) }
func equal(t *testing.T, got, want any) {
	t.Helper()
	if encoded(got) != encoded(want) {
		t.Fatalf("got %s; want %s", encoded(got), encoded(want))
	}
}

var noValue = &struct{}{}

// Independent evaluator for exactly the native intrinsics used by this template.
func resolve(t *testing.T, v any, p, conditions object) any {
	t.Helper()
	switch x := v.(type) {
	case []any:
		out := []any{}
		for _, a := range x {
			if r := resolve(t, a, p, conditions); r != noValue {
				out = append(out, r)
			}
		}
		return out
	case object:
		if a, ok := x["Ref"]; ok {
			if a == "AWS::NoValue" {
				return noValue
			}
			r, ok := p[a.(string)]
			if !ok {
				t.Fatalf("unresolved Ref %s", a)
			}
			return r
		}
		if a, ok := x["Fn::GetAtt"]; ok {
			list := a.([]any)
			return p[list[0].(string)+"."+list[1].(string)]
		}
		if a, ok := x["Fn::Sub"]; ok {
			return regexp.MustCompile(`\$\{([^}]+)\}`).ReplaceAllStringFunc(a.(string), func(s string) string {
				key := s[2 : len(s)-1]
				if _, ok := p[key]; !ok {
					t.Fatalf("unresolved Sub %s", key)
				}
				return fmt.Sprint(p[key])
			})
		}
		if a, ok := x["Fn::If"]; ok {
			list := a.([]any)
			index := 2
			if resolve(t, conditions[list[0].(string)], p, conditions).(bool) {
				index = 1
			}
			return resolve(t, list[index], p, conditions)
		}
		if a, ok := x["Fn::Not"]; ok {
			return !resolve(t, a.([]any)[0], p, conditions).(bool)
		}
		if a, ok := x["Fn::Equals"]; ok {
			list := resolve(t, a, p, conditions).([]any)
			return fmt.Sprint(list[0]) == fmt.Sprint(list[1])
		}
		if a, ok := x["Fn::Join"]; ok {
			list := a.([]any)
			items := resolve(t, list[1], p, conditions).([]any)
			ss := []string{}
			for _, item := range items {
				ss = append(ss, fmt.Sprint(item))
			}
			return strings.Join(ss, list[0].(string))
		}
		if a, ok := x["Fn::Split"]; ok {
			list := a.([]any)
			ss := strings.Split(resolve(t, list[1], p, conditions).(string), list[0].(string))
			out := []any{}
			for _, s := range ss {
				out = append(out, s)
			}
			return out
		}
		if a, ok := x["Fn::Select"]; ok {
			list := a.([]any)
			return resolve(t, list[1], p, conditions).([]any)[int(list[0].(float64))]
		}
		out := object{}
		for k, a := range x {
			out[k] = resolve(t, a, p, conditions)
		}
		return out
	default:
		return v
	}
}

func parameters() object {
	name := "aim-aws-verifier-11111111-1111-1111-1111-111111111111"
	return object{
		"AWS::Region": "eu-north-1", "AWS::AccountId": "123456789012",
		"ConnectionId": "11111111-1111-1111-1111-111111111111", "Bucket": "seller-fixture", "BucketRegion": "eu-north-1",
		"ReadKeys": []any{"exact.csv", "folder/é space.jsonl"}, "ReadPrefixes": []any{"workspace/approval/"},
		"SseKmsKeyArn": "", "RegistrationToken": strings.Repeat("a", 43), "PollIntervalMinutes": 1, "MemorySize": 1769,
		"ArtifactBucket": "public-eu-north-1", "ArtifactKey": "aws-verifier/1.0.0/" + strings.Repeat("a", 64) + "/bootstrap.zip",
		"ArtifactObjectVersion": "immutable-version", "ExpectedCodeHash": "sha256:" + strings.Repeat("a", 64),
		"ScannerVersion": "1.0.0", "ApiBaseUrl": "https://api.ai.market",
		"VerifierSecret": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:" + name + "-abcdef",
		"Ledger":         name, "Ledger.Arn": "arn:aws:dynamodb:eu-north-1:123456789012:table/" + name,
		"LogGroup": "/aws/lambda/" + name, "ExecutionRole.Arn": "arn:aws:iam::123456789012:role/execution",
		"ScheduleRole.Arn":     "arn:aws:iam::123456789012:role/schedule",
		"VerifierFunction.Arn": "arn:aws:lambda:eu-north-1:123456789012:function:" + name,
	}
}

func resolved(t *testing.T, p object) object {
	v := template(t)
	return resolve(t, v["Resources"], p, v["Conditions"].(object)).(object)
}
func props(r object, name string) object { return r[name].(object)["Properties"].(object) }
func statements(r object, role string) []any {
	return props(r, role)["Policies"].([]any)[0].(object)["PolicyDocument"].(object)["Statement"].([]any)
}

func TestExactResourcesAndRuntime(t *testing.T) {
	v := template(t)
	r := resolved(t, parameters())
	types := object{}
	for k, resource := range r {
		types[k] = resource.(object)["Type"]
	}
	equal(t, types, object{"VerifierFunction": "AWS::Lambda::Function", "ExecutionRole": "AWS::IAM::Role",
		"ScheduleRole": "AWS::IAM::Role", "VerifierSecret": "AWS::SecretsManager::Secret", "Ledger": "AWS::DynamoDB::Table",
		"PollSchedule": "AWS::Scheduler::Schedule", "LogGroup": "AWS::Logs::LogGroup"})
	f := props(r, "VerifierFunction")
	for k, want := range (object{"Runtime": "provided.al2023", "Handler": "bootstrap", "MemorySize": 1769,
		"Architectures": []string{"arm64"}, "Timeout": 900, "ReservedConcurrentExecutions": 1}) {
		equal(t, f[k], want)
	}
	equal(t, f["Code"], object{"S3Bucket": "public-eu-north-1", "S3Key": parameters()["ArtifactKey"], "S3ObjectVersion": "immutable-version"})
	// Ref enforces creation of the explicit log group before the function.
	equal(t, v["Resources"].(object)["VerifierFunction"].(object)["Properties"].(object)["Environment"].(object)["Variables"].(object)[av.EnvLogGroup], object{"Ref": "LogGroup"})
	equal(t, props(r, "VerifierSecret"), object{"Name": "aim-aws-verifier-11111111-1111-1111-1111-111111111111"})
	ledger := props(r, "Ledger")
	equal(t, ledger["BillingMode"], "PAY_PER_REQUEST")
	equal(t, ledger["KeySchema"], []object{{"AttributeName": "pk", "KeyType": "HASH"}})
	equal(t, ledger["AttributeDefinitions"], []object{{"AttributeName": "pk", "AttributeType": "S"}})
	equal(t, ledger["TimeToLiveSpecification"], object{"AttributeName": "expires_at", "Enabled": true})
	equal(t, props(r, "LogGroup")["RetentionInDays"], 30)
	if _, ok := v["Transform"]; ok {
		t.Fatal("unexpected macro")
	}
}

func TestTrustActionsScopesAndKMS(t *testing.T) {
	p := parameters()
	for _, kms := range []string{"", "arn:aws:kms:eu-north-1:123456789012:key/11111111-1111-1111-1111-111111111111"} {
		p["SseKmsKeyArn"] = kms
		r := resolved(t, p)
		for role, service := range map[string]string{"ExecutionRole": "lambda.amazonaws.com", "ScheduleRole": "scheduler.amazonaws.com"} {
			if len(props(r, role)["Policies"].([]any)) != 1 {
				t.Fatal("extra inline policy")
			}
			s := object{"Effect": "Allow", "Principal": object{"Service": service}, "Action": "sts:AssumeRole"}
			if role == "ScheduleRole" {
				s["Condition"] = object{"StringEquals": object{"aws:SourceAccount": p["AWS::AccountId"],
					"aws:SourceArn": "arn:aws:scheduler:eu-north-1:123456789012:schedule-group/default"}}
			}
			equal(t, props(r, role)["AssumeRolePolicyDocument"], object{"Version": "2012-10-17", "Statement": []object{s}})
			if _, ok := props(r, role)["ManagedPolicyArns"]; ok {
				t.Fatal("broad managed policy")
			}
		}
		want := []object{
			{"Effect": "Allow", "Action": []string{"s3:GetObject", "s3:GetObjectVersion"}, "Resource": []string{"arn:aws:s3:::seller-fixture/exact.csv", "arn:aws:s3:::seller-fixture/folder/é space.jsonl", "arn:aws:s3:::seller-fixture/workspace/approval/*"}},
			{"Effect": "Allow", "Action": []string{"secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"}, "Resource": p["VerifierSecret"]},
			{"Effect": "Allow", "Action": []string{"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"}, "Resource": p["Ledger.Arn"]},
			{"Effect": "Allow", "Action": []string{"logs:CreateLogStream", "logs:PutLogEvents"}, "Resource": "arn:aws:logs:eu-north-1:123456789012:log-group:" + p["LogGroup"].(string) + ":log-stream:*"},
		}
		if kms != "" {
			want = append(want, object{"Effect": "Allow", "Action": []string{"kms:Decrypt"}, "Resource": kms,
				"Condition": object{"StringEquals": object{"kms:ViaService": "s3.eu-north-1.amazonaws.com"}}})
		}
		equal(t, statements(r, "ExecutionRole"), want)
		equal(t, statements(r, "ScheduleRole"), []object{{"Effect": "Allow", "Action": []string{"lambda:InvokeFunction"}, "Resource": p["VerifierFunction.Arn"]}})
		s := props(r, "PollSchedule")
		equal(t, s["FlexibleTimeWindow"], object{"Mode": "OFF"})
		equal(t, s["Target"], object{"Arn": p["VerifierFunction.Arn"], "RoleArn": p["ScheduleRole.Arn"], "RetryPolicy": object{"MaximumRetryAttempts": 0}})
	}
}

func TestTokenPathAndBinaryConfigContract(t *testing.T) {
	v := template(t)
	param := v["Parameters"].(object)["RegistrationToken"].(object)
	if _, ok := param["NoEcho"]; ok {
		t.Fatal("quick-create cannot prefill NoEcho")
	}
	for _, section := range []string{"Outputs", "Metadata"} {
		if strings.Contains(encoded(v[section]), "RegistrationToken") {
			t.Fatal("token exposed in", section)
		}
	}
	if strings.Count(encoded(v["Resources"]), `"Ref":"RegistrationToken"`) != 1 {
		t.Fatal("token must reach only the environment variable")
	}
	r := resolved(t, parameters())
	env := props(r, "VerifierFunction")["Environment"].(object)["Variables"].(object)
	keys := []string{}
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := strings.Fields("AIM_AWS_CONNECTION_ID AIM_AWS_BUCKET AIM_AWS_BUCKET_REGION AIM_AWS_READ_SCOPE AIM_AWS_SECRET_ID AIM_AWS_LEDGER_TABLE AIM_AWS_REGISTRATION_TOKEN AIM_AWS_SCANNER_VERSION AIM_AWS_IMAGE_DIGEST AIM_AWS_API_BASE_URL AIM_AWS_POLL_INTERVAL_MINUTES AIM_AWS_LOG_GROUP AIM_AWS_SSE_KMS_KEY_ARN")
	sort.Strings(want)
	equal(t, keys, want)
	equal(t, env[av.EnvToken], parameters()["RegistrationToken"])
	config, err := av.ParseConfig(func(k string) string {
		if k == av.EnvMemory {
			return "1769" // Lambda supplies this reserved variable; template must not set it.
		}
		if env[k] == nil {
			return ""
		}
		return fmt.Sprint(env[k])
	})
	if err != nil || len(config.Scope.Keys) != 2 || len(config.Scope.Prefixes) != 1 {
		t.Fatal("template/binary configuration conflict", err)
	}
}

func TestRegionMemoryPollLimitsAndParameterOnlyUpdate(t *testing.T) {
	v := template(t)
	params := v["Parameters"].(object)
	equal(t, params["BucketRegion"].(object)["AllowedValues"], []string{"eu-north-1", "eu-west-1", "eu-central-1", "us-east-1", "us-west-2"})
	equal(t, params["MemorySize"].(object)["AllowedValues"], []int{1769, 3008})
	equal(t, params["MemorySize"].(object)["Default"], 1769)
	equal(t, params["PollIntervalMinutes"].(object)["AllowedValues"], []int{1, 5, 15})
	equal(t, params["PollIntervalMinutes"].(object)["Default"], 1)
	equal(t, params["ApiBaseUrl"].(object)["AllowedValues"], []string{"https://api.ai.market"})
	p := parameters()
	rules := v["Rules"].(object)["SameRegion"].(object)["Assertions"].([]any)[0].(object)["Assert"]
	equal(t, resolve(t, rules, p, v["Conditions"].(object)), true)
	p["BucketRegion"] = "us-east-1"
	equal(t, resolve(t, rules, p, v["Conditions"].(object)), false)
	p = parameters()
	before := resolved(t, p)
	for _, rate := range []int{1, 5, 15} {
		p["PollIntervalMinutes"] = rate
		after := resolved(t, p)
		want := fmt.Sprintf("rate(%d minutes)", rate)
		if rate == 1 {
			want = "rate(1 minute)"
		}
		equal(t, props(after, "PollSchedule")["ScheduleExpression"], want)
		// EnvPoll must change so registration/work uses the selected interval.
		// Everything else in all seven resolved resources must remain byte-identical.
		props(after, "PollSchedule")["ScheduleExpression"] = props(before, "PollSchedule")["ScheduleExpression"]
		props(after, "VerifierFunction")["Environment"].(object)["Variables"].(object)[av.EnvPoll] = 1
		equal(t, after, before)
	}
	for _, invalid := range []int{0, 2, 10, 16, 60} {
		for _, allowed := range params["PollIntervalMinutes"].(object)["AllowedValues"].([]any) {
			if float64(invalid) == allowed {
				t.Fatal("unsupported rate admitted")
			}
		}
	}
}

func compile(t *testing.T, source object, accepted bool) object {
	t.Helper()
	cmd := exec.Command("rtk", "proxy", "python3", "../scripts/aws-verifier-scope.py", "-")
	cmd.Stdin = strings.NewReader(encoded(source))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if (err == nil) != accepted {
		t.Fatalf("accepted=%v err=%v stderr=%s", accepted, err, &stderr)
	}
	if !accepted {
		if strings.TrimSpace(stderr.String()) != "aws_source_scope_unrepresentable" {
			t.Fatal("incorrect refusal code", &stderr)
		}
		return nil
	}
	var result object
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestScopeCompilerLimitsAndNoWildcardBroadening(t *testing.T) {
	source := object{"connection_id": parameters()["ConnectionId"], "bucket": "seller-fixture", "region": "eu-north-1", "keys": []string{}, "prefixes": []string{"workspace/approval/"}}
	result := compile(t, source, true)
	equal(t, result["object_arns"], []string{"arn:aws:s3:::seller-fixture/workspace/approval/*"})
	if result["environment_bytes_upper_bound"].(float64) > 4096 {
		t.Fatal("Lambda environment quota exceeded")
	}
	for _, bad := range []string{"", "*", "?", "prefix/*", "exact,other", `quote"`, `back\slash`, "NUL\x00", " trim ", "line\n"} {
		source["prefixes"] = []string{bad}
		compile(t, source, false)
	}
	for n := 1; n <= 51; n++ {
		keys := []string{}
		for i := 0; i < n; i++ {
			keys = append(keys, fmt.Sprintf("exact-%d.csv", i))
		}
		source["keys"], source["prefixes"] = keys, []string{}
		result = compile(t, source, n <= 50)
		if n <= 50 {
			want := []string{}
			for _, k := range keys {
				want = append(want, "arn:aws:s3:::seller-fixture/"+k)
			}
			equal(t, result["object_arns"], want)
			p := parameters()
			items := []any{}
			for _, k := range keys {
				items = append(items, k)
			}
			p["ReadKeys"], p["ReadPrefixes"] = items, []any{""}
			equal(t, statements(resolved(t, p), "ExecutionRole")[0].(object)["Resource"], want)
		}
	}
	// Each entry is valid and the count is below 50; only aggregate IAM size fails.
	source["keys"] = []string{}
	for i := 0; i < 12; i++ {
		source["keys"] = append(source["keys"].([]string), fmt.Sprintf("%d-%s", i, strings.Repeat("x", 1000)))
	}
	compile(t, source, false)
	// This fits IAM's policy limit but not Lambda's aggregate 4 KiB environment.
	source["keys"] = []string{strings.Repeat("a", 1000), strings.Repeat("b", 1000), strings.Repeat("c", 1000), strings.Repeat("d", 1000)}
	compile(t, source, false)
	source["keys"], source["prefixes"] = []string{}, []string{}
	compile(t, source, false)
	// Count union, not each list separately.
	source["keys"], source["prefixes"] = make([]string, 26), make([]string, 25)
	compile(t, source, false)
}

func TestReleaseOfflineContracts(t *testing.T) {
	cmd := exec.Command("rtk", "proxy", "python3", "../scripts/aws-verifier-release_test.py")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release tests: %v\n%s", err, b)
	}
}

func TestExactParameters(t *testing.T) {
	keys := []string{}
	for key := range template(t)["Parameters"].(object) {
		keys = append(keys, key)
	}
	want := strings.Fields("ConnectionId Bucket BucketRegion ReadKeys ReadPrefixes SseKmsKeyArn RegistrationToken PollIntervalMinutes MemorySize ArtifactBucket ArtifactKey ArtifactObjectVersion ExpectedCodeHash ScannerVersion ApiBaseUrl")
	sort.Strings(keys)
	sort.Strings(want)
	if !reflect.DeepEqual(keys, want) {
		t.Fatal("parameter drift", keys)
	}
}
