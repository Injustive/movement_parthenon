var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { c as customJoi, l as lodashExports, g as getStorage, o as openWindow, s as setStorage, R as RPC_ERROR, a as RPC_ERROR_MESSAGE, r as responseToWeb, e as extensionStorage, b as extensionSessionStorage, A as APTOS_RPC_ERROR_MESSAGE, d as getKeyPair, f as APTOS_NETWORKS, h as APTOS, i as APTOS_METHOD_TYPE, j as APTOS_POPUP_METHOD_TYPE, k as APTOS_NO_POPUP_METHOD_TYPE, m as closeWindow, n as setSessionStorage, p as extensionVersion, M as MOVEMENT_MAINNET, P as Path, q as openTab } from "./version-D6HN2BJB.js";
import { M as MESSAGE_TYPE } from "./index-BDnitI0T.js";
const COMMON_NO_POPUP_METHOD_TYPE = {
  COM__PROVIDERS: "com_providers"
};
const COMMON_METHOD_TYPE = {
  ...COMMON_NO_POPUP_METHOD_TYPE
};
class AptosRPCError extends Error {
  /**
   * Creates an instance of AptosRPCError.
   * @param code - The error code.
   * @param message - The error message.
   */
  constructor(code, message) {
    super(message);
    __publicField(this, "code");
    __publicField(this, "rpcMessage");
    this.name = "AptosRPCError";
    this.code = code;
    const errorMessage = {
      error: {
        code,
        message
      }
    };
    this.rpcMessage = errorMessage;
    Object.setPrototypeOf(this, AptosRPCError.prototype);
  }
}
class CommonRPCError extends Error {
  /**
   * Creates an instance of CommonRPCError.
   * @param code - The error code.
   * @param message - The error message.
   */
  constructor(code, message) {
    super(message);
    __publicField(this, "code");
    __publicField(this, "id");
    __publicField(this, "rpcMessage");
    this.name = "CommonRPCError";
    this.code = code;
    const errorMessage = {
      error: {
        code,
        message
      }
    };
    this.rpcMessage = errorMessage;
    Object.setPrototypeOf(this, CommonRPCError.prototype);
  }
}
const aptosSignMessageSchema = () => customJoi.array().label("params").required().items(
  customJoi.object({
    address: customJoi.boolean().optional(),
    application: customJoi.boolean().optional(),
    chainId: customJoi.boolean().optional(),
    message: customJoi.string().required(),
    nonce: customJoi.string().required()
  }).required()
);
const aptosChangeNetworkParamsSchema = (chainIds) => customJoi.array().label("params").required().items(
  customJoi.number().label("chainId").valid(...chainIds).required()
);
let localQueues = [];
const setQueues = lodashExports.debounce(
  async () => {
    const queues = localQueues;
    localQueues = [];
    const currentQueue = await getStorage("queues");
    const window = await openWindow();
    await setStorage("queues", [
      ...currentQueue.map((item) => ({ ...item, windowId: window?.id })),
      ...queues.map((item) => ({ ...item, windowId: window?.id }))
    ]);
  },
  500,
  { leading: true }
);
async function cstob(request) {
  if (request.line === "COMMON") {
    const commonMethods = Object.values(COMMON_METHOD_TYPE);
    const { message, messageId, origin } = request;
    try {
      if (!message?.method || !commonMethods.includes(message.method)) {
        throw new CommonRPCError(
          RPC_ERROR.METHOD_NOT_SUPPORTED,
          RPC_ERROR_MESSAGE[RPC_ERROR.METHOD_NOT_SUPPORTED]
        );
      }
    } catch (e) {
      if (e instanceof CommonRPCError) {
        responseToWeb({
          response: e.rpcMessage,
          message,
          messageId,
          origin
        });
        return;
      }
      responseToWeb({
        response: {
          error: {
            code: RPC_ERROR.INTERNAL,
            message: `${RPC_ERROR_MESSAGE[RPC_ERROR.INTERNAL]}`
          }
        },
        message,
        messageId,
        origin
      });
    }
  }
  if (request.line === "APTOS") {
    const chain = APTOS;
    const aptosMethods = Object.values(APTOS_METHOD_TYPE);
    const aptosPopupMethods = Object.values(
      APTOS_POPUP_METHOD_TYPE
    );
    const aptosNoPopupMethods = Object.values(
      APTOS_NO_POPUP_METHOD_TYPE
    );
    const {
      currentAccountAllowedOrigins,
      additionalAptosNetworks,
      currentAccount,
      allowedOrigins,
      currentAptosNetwork
    } = await extensionStorage();
    const { currentPassword } = await extensionSessionStorage();
    const { message, messageId, origin } = request;
    if (currentAccount.type === "LEDGER") {
      throw new AptosRPCError(
        RPC_ERROR.LEDGER_UNSUPPORTED_CHAIN,
        APTOS_RPC_ERROR_MESSAGE[RPC_ERROR.LEDGER_UNSUPPORTED_CHAIN]
      );
    }
    try {
      if (!message?.method || !aptosMethods.includes(message.method)) {
        throw new AptosRPCError(
          RPC_ERROR.UNSUPPORTED_METHOD,
          APTOS_RPC_ERROR_MESSAGE[RPC_ERROR.UNSUPPORTED_METHOD]
        );
      }
      const { method } = message;
      if (aptosPopupMethods.includes(method)) {
        if (method === "aptos_connect" || method === "aptos_account") {
          if (currentAccountAllowedOrigins.includes(origin) && currentPassword) {
            const keyPair = getKeyPair(
              currentAccount,
              chain,
              currentPassword
            );
            const result = {
              address: keyPair.accountAddress.toString(),
              publicKey: keyPair.publicKey.toString()
            };
            responseToWeb({
              response: {
                result
              },
              message,
              messageId,
              origin
            });
          } else {
            localQueues.push(request);
            void setQueues();
          }
        }
        if (method === "aptos_changeNetwork") {
          const { params } = message;
          const networkChainIds = [
            ...APTOS_NETWORKS,
            ...additionalAptosNetworks
          ].map((item) => item.chainId);
          const schema = aptosChangeNetworkParamsSchema(networkChainIds);
          try {
            const validatedParams = await schema.validateAsync(
              params
            );
            if (params[0] === currentAptosNetwork.chainId) {
              const result = {
                success: true
              };
              responseToWeb({
                response: {
                  result
                },
                message,
                messageId,
                origin
              });
              return;
            }
            localQueues.push({
              ...request,
              message: {
                ...request.message,
                method,
                params: [...validatedParams]
              }
            });
            void setQueues();
          } catch (e) {
            if (e instanceof AptosRPCError) {
              throw e;
            }
            throw new AptosRPCError(RPC_ERROR.INVALID_PARAMS, `${e}`);
          }
        }
        if (method === "aptos_signTransaction") {
          const { params } = message;
          try {
            localQueues.push({
              ...request,
              message: {
                ...request.message,
                method,
                params: [...params]
              }
            });
            void setQueues();
          } catch (e) {
            if (e instanceof AptosRPCError) {
              throw e;
            }
            throw new AptosRPCError(RPC_ERROR.INVALID_PARAMS, `${e}`);
          }
        }
        if (method === "aptos_signAndSubmitTransaction") {
          const { params } = message;
          try {
            localQueues.push({
              ...request,
              message: {
                ...request.message,
                method,
                params: [...params]
              }
            });
            void setQueues();
          } catch (e) {
            if (e instanceof AptosRPCError) {
              throw e;
            }
            throw new AptosRPCError(RPC_ERROR.INVALID_PARAMS, `${e}`);
          }
        }
        if (method === "aptos_signMessage") {
          const { params } = message;
          try {
            const schema = aptosSignMessageSchema();
            const validatedParams = await schema.validateAsync(
              params
            );
            localQueues.push({
              ...request,
              message: {
                ...request.message,
                method,
                params: [...validatedParams]
              }
            });
            void setQueues();
          } catch (e) {
            if (e instanceof AptosRPCError) {
              throw e;
            }
            throw new AptosRPCError(RPC_ERROR.INVALID_PARAMS, `${e}`);
          }
        }
      } else if (aptosNoPopupMethods.includes(method)) {
        if (method === "aptos_isConnected") {
          const result = !!currentAccountAllowedOrigins.includes(origin);
          responseToWeb({
            response: {
              result
            },
            message,
            messageId,
            origin
          });
        }
        if (method === "aptos_disconnect") {
          const newAllowedOrigins = allowedOrigins.filter(
            (item) => !(item.accountId === currentAccount.id && item.origin === origin)
          );
          await setStorage("allowedOrigins", newAllowedOrigins);
          const result = null;
          responseToWeb({
            response: {
              result
            },
            message,
            messageId,
            origin
          });
        }
        if (method === "aptos_network") {
          const result = {
            name: currentAptosNetwork.networkName,
            chainId: currentAptosNetwork.chainId,
            url: currentAptosNetwork.restURL
          };
          responseToWeb({
            response: {
              result
            },
            message,
            messageId,
            origin
          });
        }
      } else {
        throw new AptosRPCError(
          RPC_ERROR.INVALID_REQUEST,
          RPC_ERROR_MESSAGE[RPC_ERROR.INVALID_REQUEST]
        );
      }
    } catch (e) {
      if (e instanceof AptosRPCError) {
        responseToWeb({
          response: e.rpcMessage,
          message,
          messageId,
          origin
        });
        return;
      }
      responseToWeb({
        response: {
          error: {
            code: RPC_ERROR.INTERNAL,
            message: `${RPC_ERROR_MESSAGE[RPC_ERROR.INTERNAL]}`
          }
        },
        message,
        messageId,
        origin
      });
    }
  }
}
function background() {
  chrome.runtime.onMessage.addListener(
    (request, _, sendResponse) => {
      if (request?.type === MESSAGE_TYPE.REQUEST__CONTENT_SCRIPT_TO_BACKGROUND) {
        void cstob(request);
        sendResponse();
      }
    }
  );
  chrome.storage.onChanged.addListener((changes) => {
    for (const [key, { newValue }] of Object.entries(changes)) {
      if (key === "queues") {
        const newQueues = newValue;
        let text = "";
        if (newQueues && newQueues.length > 0) {
          text = String(newQueues.length);
        }
        void chrome.action.setBadgeText({ text });
      }
    }
  });
  chrome.windows.onRemoved.addListener((windowId) => {
    void (async () => {
      const queues = await getStorage("queues");
      const currentWindowIds = queues.filter((item) => typeof item.windowId === "number").map((item) => item.windowId);
      const currentWindowId = await getStorage("windowId");
      if (typeof currentWindowId === "number") {
        currentWindowIds.push(currentWindowId);
      }
      const windowIds = Array.from(new Set(currentWindowIds));
      await setStorage("windowId", null);
      if (windowIds.includes(windowId)) {
        queues.forEach((queue) => {
          responseToWeb({
            response: {
              error: {
                code: RPC_ERROR.USER_REJECTED_REQUEST,
                message: `${RPC_ERROR_MESSAGE[RPC_ERROR.USER_REJECTED_REQUEST]}`
              }
            },
            message: queue.message,
            messageId: queue.messageId,
            origin: queue.origin
          });
          void closeWindow(queue.windowId);
        });
        await setStorage("queues", []);
      }
    })();
  });
  chrome.runtime.onStartup.addListener(() => {
    void (async () => {
      await setStorage("queues", []);
      await setStorage("windowId", null);
      await setSessionStorage("password", null);
    })();
  });
  chrome.runtime.onInstalled.addListener((details) => {
    void (async () => {
      if (details.reason === "update") {
        const extensionManifest = chrome.runtime.getManifest();
        if (extensionManifest.version === extensionVersion) {
          void (async () => {
            await setStorage("allowedChainIds", [
              ...await getStorage("allowedChainIds"),
              MOVEMENT_MAINNET.id
            ]);
          })();
        }
      }
      if (details.reason === "install") {
        await setStorage("queues", []);
        await setStorage("windowId", null);
        await setStorage("accounts", []);
        await setStorage("accountName", {});
        await setStorage("additionalChains", []);
        await setStorage("encryptedPassword", null);
        await setStorage("selectedAccountId", "");
        await setStorage("addressBook", []);
        await setStorage("rootPath", Path.DASHBOARD);
        await setStorage("homeTabIndex", {
          aptos: 0
        });
        await setStorage("language", "");
        await setStorage("currency", "");
        await setStorage("allowedChainIds", [APTOS.id]);
        await setStorage("allowedOrigins", []);
        await setStorage("selectedChainId", "");
        await setStorage("selectedAptosNetworkId", APTOS_NETWORKS[0].id);
        await setStorage("address", {});
        await setSessionStorage("password", null);
        await openTab();
      }
    })();
  });
  void chrome.action.setBadgeBackgroundColor({ color: "#7C4FFC" });
  void chrome.action.setBadgeText({ text: "" });
}
background();
