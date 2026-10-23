# Vulnerable side of the regex2shell differential pair.
# Official image, one patch below the Onigmo fixes (pre ruby/ruby#13332/#19020/#16801).
FROM ruby:3.4.11

RUN gem install org-ruby -v 0.9.12 --no-document

WORKDIR /app
COPY server.rb render.rb /app/
ENV REQUEST_TIMEOUT=15
EXPOSE 8080
CMD ["ruby", "/app/server.rb"]
