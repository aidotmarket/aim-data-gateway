//go:build d7spike

package awsverification

// D7 measurement hook (S1791 spike branch only, never merged).
func NewSourceReadAhead(client S3, bucket string, objects []Object, ahead int64) (*Source, error) {
	s, err := NewSource(client, bucket, objects)
	if err == nil {
		s.readAhead = ahead
	}
	return s, err
}
