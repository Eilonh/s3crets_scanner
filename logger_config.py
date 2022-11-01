import logging
import sys


def logger_conf():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    if not len(logger.handlers):
        for module in [
            "boto3",
            "botocore",
            "urllib3",
            "gql.transport.aiohttp",
            "asyncio",
            "s3transfer"
        ]:
            logging.getLogger(module).setLevel(logging.CRITICAL)
        fh = logging.FileHandler('logger.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(asctime)s - %(name)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(logging.StreamHandler(sys.stdout))

        
#ssgahsa
