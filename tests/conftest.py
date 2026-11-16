import pytest

from scamcheck.model import ScamModel
from scamcheck.train import main as train_main


@pytest.fixture(scope="session")
def model_path(tmp_path_factory):
    """Train a real model once for the whole test run (takes a few seconds)."""
    out = tmp_path_factory.mktemp("model") / "scamcheck.joblib"
    train_main(["--out", str(out), "--metrics", str(out.with_name("metrics.json"))])
    return out


@pytest.fixture(scope="session")
def model(model_path):
    return ScamModel.load(model_path)
