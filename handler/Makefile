# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

PROTOSRCS := endorsement_response.proto

PROTOPATHS := ../proto

all-hook-pre test-hook-pre lint-hook-pre:
	$(MAKE) -C ../proto protogen
	$(MAKE) protogen

include ../mk/common.mk
include ../mk/pkg.mk
include ../mk/lint.mk
include ../mk/proto.mk
include ../mk/test.mk
