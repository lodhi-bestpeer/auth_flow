class ResponseHandler {
    async handleServiceResponse(req, res, returnData) {
        if (returnData.success) {
            return res.status(200).json(returnData);
        }
        return res.status(400).json({ success: false, message: returnData.error });
    }
}

export default ResponseHandler;
