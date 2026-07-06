"""AWS access seam.

Everything that touches AWS goes through :mod:`polyphemus.aws.clients`. In
``mock`` mode the factory functions return deterministic in-memory fakes so the
pipeline runs offline; in ``aws`` mode they would return real boto3 clients.
Pipeline modules import from here and never import boto3 directly.
"""
