deps=$(go list -f '{{join .Deps "\n"}}' | grep \.com)

for d in ${deps} ; do
  echo "${d}"
  go get -u ${d}
  go build ${d}
  go install ${d}
done
