import re
from urllib.parse import urlparse


class JSExtractor:

    REST_PATTERNS = [
        re.compile(r'["\'](/rest/[a-zA-Z0-9\-_/]+)["\']'),
        re.compile(r'["\'](/api/[a-zA-Z0-9_\-\/]+)["\']'),
        re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-\/]+)["\']'),
        re.compile(r'fetch\(["\'](.*?)["\']'),
        re.compile(r'axios\.(?:get|post|put|delete)\(["\'](.*?)["\']')
    ]

    GRAPHQL_PATTERN = re.compile(r'["\'](/graphql[^"\']*)["\']')
    PARAM_PATTERN = re.compile(r'\?([a-zA-Z0-9\-=&]+)')

    @staticmethod
    def normalize_route(route):
        if not route:
            return None
        parsed = urlparse(route)
        path = parsed.path
        path = re.sub(r'/\d+', '/{id}', path)
        return path.rstrip("/")

    def extract(self, content: str) -> dict:
        routes = set()
        graphql = set()
        parameters = set()

        for pattern in self.REST_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                normalized = self.normalize_route(match)
                if normalized:
                    routes.add(normalized)

                param_match = self.PARAM_PATTERN.search(match)
                if param_match:
                    params = param_match.group(1).split("&")
                    for p in params:
                        key = p.split("=")[0]
                        parameters.add(key)

        gql_matches = self.GRAPHQL_PATTERN.findall(content)
        for g in gql_matches:
            normalized = self.normalize_route(g)
            if normalized:
                graphql.add(normalized)

        return {
            "routes": sorted(routes),
            "graphql": sorted(graphql),
            "parameters": sorted(parameters)
        }
