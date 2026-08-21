from __future__ import annotations

from flow_processor.pipeline import FlowPipeline

_ACCEPT_LINE = "2 123456789010 eni-1235b8ca 10.0.1.5 10.0.0.220 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"

_NSG_BLOB = {
    "records": [
        {
            "time": "2020-04-26T15:00:35.0000000Z",
            "resourceId": "/SUBSCRIPTIONS/x/NETWORKSECURITYGROUPS/NSG1",
            "properties": {
                "Version": 2,
                "flows": [
                    {
                        "rule": "UserRule_default-allow-ssh",
                        "flows": [
                            {
                                "mac": "000D3AABBCC",
                                "flowTuples": [
                                    "1587913235,10.0.0.4,10.0.0.5,52033,22,T,I,A,B,10,1155,8,660",
                                    "1587913240,10.0.0.4,10.0.0.6,52099,3389,T,I,D,B,1,60,0,0",
                                ],
                            }
                        ],
                    }
                ],
            },
        }
    ]
}


def test_pipeline_processes_aws_events():
    pipe = FlowPipeline()
    batch = [
        {
            "event_type": "aws.vpc_flow_log",
            "tenant_id": "tenant-acme",
            "asset": {"asset_id": "vpc-eni-1235b8ca"},
            "payload": {"raw_line": _ACCEPT_LINE},
        }
        for _ in range(8)
    ]
    features = pipe.process_events(batch)
    assert isinstance(features, list)
    assert pipe.processed == 8
    assert pipe.errors == 0


def test_pipeline_fans_out_azure_nsg_blob_into_multiple_flows():
    pipe = FlowPipeline()
    # One raw NSG blob event fans out into 2 flow tuples; repeat to fill a window.
    batch = [
        {
            "event_type": "azure.nsg_flow_log",
            "tenant_id": "tenant-acme",
            "payload": {"nsg_blob": _NSG_BLOB, "asset_id": "nsg-host-01"},
        }
        for _ in range(4)
    ]
    features = pipe.process_events(batch)
    assert isinstance(features, list)
    # 4 raw blobs counted as 4 processed events, but each yields 2 flows (8 total).
    assert pipe.processed == 4
    assert pipe.errors == 0
