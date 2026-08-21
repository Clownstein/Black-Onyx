package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var safeObjectSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// PcapArtifact is durable metadata published to Kafka after object upload.
type PcapArtifact struct {
	URI      string
	SHA256   string
	Size     int64
	Filename string
}

// PcapObjectStore is deliberately small so upload/ownership behavior can be
// verified without a live MinIO server.
type PcapObjectStore interface {
	Put(
		ctx context.Context,
		tenantID string,
		eventID string,
		filename string,
		data []byte,
	) (PcapArtifact, error)
	ValidateURI(tenantID string, uri string) error
}

type minioPcapStore struct {
	client     *minio.Client
	bucket     string
	region     string
	bucketOnce sync.Once
	bucketErr  error
}

func NewMinioPcapStore(
	endpoint string,
	accessKey string,
	secretKey string,
	bucket string,
	region string,
) (PcapObjectStore, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, nil
	}
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("MINIO_ACCESS_KEY and MINIO_SECRET_KEY are required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse MINIO_ENDPOINT: %w", err)
	}
	host := parsed.Host
	secure := parsed.Scheme == "https"
	if host == "" {
		host = parsed.Path
	}
	client, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure,
		Region: region,
	})
	if err != nil {
		return nil, fmt.Errorf("create MinIO client: %w", err)
	}
	if !safeObjectSegment.MatchString(bucket) {
		return nil, errors.New("MINIO_PCAP_BUCKET contains unsafe characters")
	}
	return &minioPcapStore{client: client, bucket: bucket, region: region}, nil
}

func validateObjectIdentity(tenantID string, eventID string) error {
	if !safeObjectSegment.MatchString(tenantID) {
		return errors.New("tenant_id contains unsafe object-key characters")
	}
	if !safeObjectSegment.MatchString(eventID) {
		return errors.New("event_id contains unsafe object-key characters")
	}
	return nil
}

func safeFilename(filename string) string {
	clean := path.Base(strings.ReplaceAll(strings.TrimSpace(filename), `\`, "/"))
	if clean == "." || clean == "/" || clean == "" || !safeObjectSegment.MatchString(clean) {
		return "capture.pcap"
	}
	return clean
}

func (s *minioPcapStore) ensureBucket(ctx context.Context) error {
	s.bucketOnce.Do(func() {
		exists, err := s.client.BucketExists(ctx, s.bucket)
		if err != nil {
			s.bucketErr = err
			return
		}
		if !exists {
			s.bucketErr = s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{
				Region: s.region,
			})
		}
	})
	return s.bucketErr
}

func (s *minioPcapStore) Put(
	ctx context.Context,
	tenantID string,
	eventID string,
	filename string,
	data []byte,
) (PcapArtifact, error) {
	if err := validateObjectIdentity(tenantID, eventID); err != nil {
		return PcapArtifact{}, err
	}
	if len(data) == 0 {
		return PcapArtifact{}, errors.New("PCAP payload is empty")
	}
	if err := s.ensureBucket(ctx); err != nil {
		return PcapArtifact{}, fmt.Errorf("ensure MinIO bucket: %w", err)
	}
	filename = safeFilename(filename)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	objectName := path.Join(tenantID, eventID, digest[:16]+"-"+filename)
	_, err := s.client.PutObject(
		ctx,
		s.bucket,
		objectName,
		bytes.NewReader(data),
		int64(len(data)),
		minio.PutObjectOptions{
			ContentType: "application/vnd.tcpdump.pcap",
			UserMetadata: map[string]string{
				"tenant-id": tenantID,
				"event-id":  eventID,
				"sha256":    digest,
			},
		},
	)
	if err != nil {
		return PcapArtifact{}, fmt.Errorf("upload PCAP to MinIO: %w", err)
	}
	return PcapArtifact{
		URI:      fmt.Sprintf("s3://%s/%s", s.bucket, objectName),
		SHA256:   digest,
		Size:     int64(len(data)),
		Filename: filename,
	}, nil
}

func (s *minioPcapStore) ValidateURI(tenantID string, rawURI string) error {
	if !safeObjectSegment.MatchString(tenantID) {
		return errors.New("tenant_id contains unsafe object-key characters")
	}
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme != "s3" {
		return errors.New("PCAP uri must use s3://")
	}
	if parsed.Host != s.bucket {
		return errors.New("PCAP uri bucket is not the configured tenant artifact bucket")
	}
	key := strings.TrimPrefix(parsed.Path, "/")
	if !strings.HasPrefix(key, tenantID+"/") {
		return errors.New("PCAP uri is not owned by the request tenant")
	}
	return nil
}
