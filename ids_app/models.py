from django.db import models

class Packet(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=50)
    length = models.IntegerField()
    is_attack = models.BooleanField(default=False)
    attack_type = models.CharField(max_length=100, null=True, blank=True)
    def __str__(self):
        """
        Return a string representation of the Packet object.

        Returns:
            str: The string representation of the Packet object.
        """
        # Format the source IP, destination IP, and destination port into a string
        return f"{self.src_ip} -> {self.dst_ip}:{self.dst_port}"

class NetworkActivity(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    activity_type = models.CharField(max_length=100)
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    dst_port = models.IntegerField()
    report = models.TextField()

    def __str__(self):
        """
        Return a string representation of the NetworkActivity object.

        Returns:
            str: The string representation of the NetworkActivity object.
        """
        # Format the source IP, destination IP, and destination port into a string
        # along with the activity type
        return (
            f"{self.activity_type} - {self.src_ip} -> {self.dst_ip}:{self.dst_port}"
        )
