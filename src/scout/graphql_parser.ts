export interface GraphQLFieldArg {
  name: string;
  typeName: string;
  isNonNull: boolean;
}

export interface GraphQLField {
  name: string;
  args: GraphQLFieldArg[];
  isObjectTarget: boolean; // True if takes an ID or resource key
}

export interface GraphQLSchemaSummary {
  queries: GraphQLField[];
  mutations: GraphQLField[];
  rawTypesCount: number;
}

/**
 * GRAPHQL SCHEMA SCOUT & INTROSPECTION PARSER
 * Queries __schema to map queries, mutations, and vulnerable ID/resource arguments.
 */
export class GraphQLParser {
  public static readonly INTROSPECTION_QUERY = `
    query AshbornIntrospection {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields(includeDeprecated: false) {
            name
            args {
              name
              type {
                name
                kind
                ofType {
                  name
                  kind
                }
              }
            }
          }
        }
      }
    }
  `.replace(/\s+/g, ' ').trim();

  public static generateIntrospectionPayload(): string {
    return JSON.stringify({ query: this.INTROSPECTION_QUERY });
  }

  public static parseSchema(introspectionResponse: string | Record<string, unknown>): GraphQLSchemaSummary {
    const raw = typeof introspectionResponse === 'string'
      ? JSON.parse(introspectionResponse)
      : introspectionResponse;

    const schema = (raw.data?.__schema || raw.__schema || raw) as {
      queryType?: { name: string };
      mutationType?: { name: string };
      types?: Array<{
        name: string;
        kind: string;
        fields?: Array<{
          name: string;
          args?: Array<{
            name: string;
            type?: {
              name?: string;
              kind?: string;
              ofType?: { name?: string; kind?: string };
            };
          }>;
        }>;
      }>;
    };

    const queries: GraphQLField[] = [];
    const mutations: GraphQLField[] = [];

    if (!schema.types || !Array.isArray(schema.types)) {
      return { queries, mutations, rawTypesCount: 0 };
    }

    const queryTypeName = schema.queryType?.name || 'Query';
    const mutationTypeName = schema.mutationType?.name || 'Mutation';

    for (const t of schema.types) {
      if (!t.fields || !Array.isArray(t.fields)) continue;

      const isQueryType = t.name === queryTypeName;
      const isMutationType = t.name === mutationTypeName;

      if (!isQueryType && !isMutationType) continue;

      for (const f of t.fields) {
        const args: GraphQLFieldArg[] = [];
        let isObjectTarget = false;

        if (Array.isArray(f.args)) {
          for (const a of f.args) {
            const typeName = a.type?.name || a.type?.ofType?.name || 'String';
            const isNonNull = a.type?.kind === 'NON_NULL';
            args.push({ name: a.name, typeName, isNonNull });

            // Identify object identifiers: id, userId, invoiceId, accountId, orderId, uuid
            if (/^(id|_id|uuid|[a-zA-Z0-9_]+Id)$/i.test(a.name)) {
              isObjectTarget = true;
            }
          }
        }

        const fieldItem: GraphQLField = {
          name: f.name,
          args,
          isObjectTarget,
        };

        if (isQueryType) {
          queries.push(fieldItem);
        } else if (isMutationType) {
          mutations.push(fieldItem);
        }
      }
    }

    return {
      queries,
      mutations,
      rawTypesCount: schema.types.length,
    };
  }
}
