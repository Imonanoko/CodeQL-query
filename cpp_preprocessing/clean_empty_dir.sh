#!/usr/bin/env bash
find cpp_query_output/ -mindepth 1 -type d -empty -delete
find cpp_query_output/ -mindepth 1 -type d | wc -l