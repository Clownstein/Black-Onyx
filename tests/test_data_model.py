"""Tests for the DataModel."""

from black_onyx.models.data_model import DataModel


class TestDataModel:
    def test_default_values(self):
        """Test that all fields have correct default values."""
        model = DataModel()
        assert model.body_text is None
        assert model.source_file is None
        assert model.chunk_index == 0
        assert model.total_chunks == 1
        assert model.payload_type == "text"
        assert model.bitcoin_address == []
        assert model.emails == []
        assert model.person_name == []

    def test_string_coercion(self):
        """Test that string values are coerced to single-element lists."""
        model = DataModel(emails="test@example.com")
        assert model.emails == ["test@example.com"]

    def test_empty_string_coercion(self):
        """Test that empty strings become empty lists."""
        model = DataModel(emails="")
        assert model.emails == []

    def test_none_coercion(self):
        """Test that None values become empty lists for list fields."""
        model = DataModel(emails=None)
        assert model.emails == []

    def test_list_field_assignment(self):
        """Test that list values are preserved."""
        model = DataModel(emails=["a@test.com", "b@test.com"])
        assert model.emails == ["a@test.com", "b@test.com"]

    def test_merge_metadata_lists(self):
        """Test merging metadata with list fields (deduplication)."""
        model = DataModel(emails=["existing@test.com"])
        model.merge_metadata({"emails": ["new@test.com", "existing@test.com"]})
        assert model.emails == ["existing@test.com", "new@test.com"]

    def test_merge_metadata_scalar(self):
        """Test merging metadata with scalar fields."""
        model = DataModel()
        model.merge_metadata({"title": "Test Title"})
        assert model.title == "Test Title"

    def test_merge_metadata_dict_to_list(self):
        """Test merging dict metadata into list fields (social_profiles)."""
        model = DataModel()
        model.merge_metadata({"social_profiles": {"twitter": "user1"}})
        assert model.social_profiles == ["twitter:user1"]

    def test_model_dump(self):
        """Test that model_dump() produces a valid dict."""
        model = DataModel(body_text="test", emails=["a@test.com"])
        dumped = model.model_dump()
        assert dumped["body_text"] == "test"
        assert dumped["emails"] == ["a@test.com"]
        assert dumped["chunk_index"] == 0

    def test_image_fields(self):
        """Test image-specific fields."""
        model = DataModel(
            payload_type="image",
            image_width=800,
            image_height=600,
            image_format="PNG",
            gps_latitude=40.7128,
            gps_longitude=-74.0060,
            ocr_text="Extracted text",
        )
        assert model.payload_type == "image"
        assert model.image_width == 800
        assert model.gps_latitude == 40.7128
        assert model.ocr_text == "Extracted text"
