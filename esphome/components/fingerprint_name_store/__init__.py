import esphome.codegen as cg
import esphome.config_validation as cv


CODEOWNERS = ["@kytos22"]
CONFIG_SCHEMA = cv.Schema({})


async def to_code(_config):
    cg.add_global(
        cg.RawStatement(
            '#include "esphome/components/fingerprint_name_store/fingerprint_name_store.h"'
        ),
        prepend=True,
    )
