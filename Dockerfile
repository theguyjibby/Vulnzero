# Use a lightweight Linux distribution as the base image
FROM kalilinux/kali-rolling

# Update package lists and install Nikto
RUN apt-get update && apt-get install -y nikto

# Set the entrypoint to the Nikto command-line tool.
ENTRYPOINT ["nikto"]

# Ensure we call the 'nikto' command inside the container
CMD ["run", "--rm", "-v", "mount_spec", "nikto-scanner", "-h", "target_url", "-o", "/tmp/output_filename", "-Format", "json"]

