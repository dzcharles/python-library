import logging
import logger_config

default_log = logging.getLogger()
server_log = logging.getLogger(name="serverlogs")
application_log = logging.getLogger(name="applicationlogs")
logger_config.setup_logging()

def main():
    default_log.info("This is a default log message.")
    server_log.info("This is a server log message.")
    application_log.info("This is an application log message.")
    

if __name__ == "__main__":
    main()