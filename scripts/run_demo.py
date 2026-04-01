import argparse
import logging
import warnings

from src.utils.config import load_settings


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Weapon + Action Threat Detection")
    p.add_argument("--video", help="Path to input video")
    p.add_argument("--camera", type=int, help="Camera index for live webcam (e.g. 0)")
    p.add_argument("--config", required=True, help="Path to YAML config")
    return p.parse_args()


def main() -> None:
    # Silence known non-blocking dependency warnings for cleaner console output.
    warnings.filterwarnings(
        "ignore",
        message=r".*torch\.meshgrid: in an upcoming release.*",
        category=UserWarning,
    )
    warnings.filterwarnings(
        "ignore",
        message=r'.*"FileClient" will be deprecated in future.*',
    )
    warnings.filterwarnings(
        "ignore",
        message=r'.*"HardDiskBackend" is the alias of "LocalBackend".*',
    )
    warnings.filterwarnings(
        "ignore",
        message=r".*Fail to import ``MultiScaleDeformableAttention``.*",
    )
    logging.getLogger("mmengine").setLevel(logging.ERROR)

    args = parse_args()
    cfg = load_settings(args.config)
    from src.pipeline.engine import ThreatEngine

    engine = ThreatEngine(cfg)
    if args.camera is not None:
        engine.run_camera(args.camera)
    elif args.video:
        engine.run_video(args.video)
    else:
        raise ValueError("Provide either --video <path> or --camera <index>.")


if __name__ == "__main__":
    main()
