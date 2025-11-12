from rest_framework import serializers

class ConnectSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    ip_address = serializers.IPAddressField()
    connection_name = serializers.CharField()

class InitiateSerializer(serializers.Serializer):
    name = serializers.CharField()
    directory = serializers.CharField()
    fullname = serializers.CharField()
    connection_name = serializers.CharField()

class FilterSerializer(serializers.Serializer):
    connection_name = serializers.CharField()

class TesterSerializer(serializers.Serializer):
    connection_name = serializers.CharField()
    id = serializers.CharField()