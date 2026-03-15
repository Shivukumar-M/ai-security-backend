# backend/app/utils/helper.py
import joblib
import logging
from huggingface_hub import hf_hub_download

logger = logging.getLogger(__name__)

# Your HF model repo
HF_REPO_ID = "biloxec/malware-detector"


def load_ml_model(filename: str):
    """
    Universal loader for ML models stored on HuggingFace.
    """
    try:
        logger.info(f"⬇ Downloading {filename} from HF ({HF_REPO_ID})")
        
        path = hf_hub_download(
            repo_id=HF_REPO_ID,
            filename=filename
        )
        
        model = joblib.load(path)
        logger.info(f"Loaded ML file: {path}")
        return model
    
    except Exception as e:
        logger.error(f"❌ Failed loading model {filename}: {e}")
        raise RuntimeError(f"Could not load {filename}")
